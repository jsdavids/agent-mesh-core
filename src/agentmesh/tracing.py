"""OpenTelemetry setup shared by the gateway and agents.

Traces export over OTLP/HTTP, which Jaeger, Arize Phoenix and most
collectors accept (Jaeger: http://localhost:4318/v1/traces, Phoenix:
http://localhost:6006/v1/traces).
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping

from opentelemetry import propagate, trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

_configured = False


def setup_tracing(service_name: str, exporter: str = "none", endpoint: str | None = None) -> trace.Tracer:
    global _configured
    if not _configured and exporter != "none":
        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        if exporter == "console":
            provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        elif exporter == "otlp":
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            provider.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint) if endpoint else OTLPSpanExporter())
            )
        else:
            raise ValueError(f"unknown tracing exporter {exporter!r}")
        trace.set_tracer_provider(provider)
        _configured = True
    return trace.get_tracer(service_name)


def extract_context(headers: Mapping[str, str]):
    return propagate.extract(dict(headers))


def inject_headers(headers: MutableMapping[str, str]) -> MutableMapping[str, str]:
    propagate.inject(headers)
    return headers


def current_trace_id() -> str | None:
    ctx = trace.get_current_span().get_span_context()
    return format(ctx.trace_id, "032x") if ctx.is_valid else None
