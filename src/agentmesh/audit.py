"""Append-only audit log of every call the gateway sees.

With `hash_chain` on, each record stores the hash of the previous record, so
editing, deleting or reordering any line breaks every hash after it. A plain
hash chain can be recomputed by someone who rewrites the whole file, so pass
an HMAC key (held outside the agents' sandbox) to make the chain unforgeable,
and/or publish the head hash somewhere the writer can't change.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode()


def _digest(record: dict[str, Any], key: bytes | None) -> str:
    body = _canonical({k: v for k, v in record.items() if k != "hash"})
    if key:
        return hmac.new(key, body, hashlib.sha256).hexdigest()
    return hashlib.sha256(body).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None, hash_chain: bool = True, hmac_key: bytes | None = None):
        self.path = Path(path) if path else None
        self.hash_chain = hash_chain
        self._key = hmac_key
        self._lock = threading.Lock()
        self._seq = 0
        self._head = GENESIS
        self.records: list[dict[str, Any]] = []  # in-memory tail for /metrics and tests
        self.counts: Counter[str] = Counter()
        if self.path and self.path.exists():
            self._resume()

    def _resume(self) -> None:
        last = None
        with self.path.open() as fh:
            for line in fh:
                if line.strip():
                    last = json.loads(line)
        if last:
            self._seq = last["seq"]
            self._head = last.get("hash", GENESIS)

    @property
    def head(self) -> str:
        return self._head

    def record(self, **event: Any) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            rec = {"seq": self._seq, "ts": time.time(), **event}
            if self.hash_chain:
                rec["prev"] = self._head
                rec["hash"] = _digest(rec, self._key)
                self._head = rec["hash"]
            self.records.append(rec)
            if len(self.records) > 10_000:
                del self.records[:5_000]
            self.counts[event.get("decision", "unknown")] += 1
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a") as fh:
                    fh.write(_canonical(rec).decode() + "\n")
            return rec


@dataclass
class VerifyResult:
    ok: bool
    records: int
    bad_seq: int | None = None
    reason: str = ""


def verify_chain(path: str | Path, hmac_key: bytes | None = None) -> VerifyResult:
    prev, expected_seq, n = GENESIS, 1, 0
    with Path(path).open() as fh:
        for line in fh:
            if not line.strip():
                continue
            rec = json.loads(line)
            n += 1
            seq = rec.get("seq")
            if seq != expected_seq:
                return VerifyResult(False, n, seq, f"expected seq {expected_seq}, found {seq}")
            if rec.get("prev") != prev:
                return VerifyResult(False, n, seq, "prev hash does not match the previous record")
            if not hmac.compare_digest(rec.get("hash", ""), _digest(rec, hmac_key)):
                return VerifyResult(False, n, seq, "record hash does not match its contents")
            prev, expected_seq = rec["hash"], expected_seq + 1
    return VerifyResult(True, n)
