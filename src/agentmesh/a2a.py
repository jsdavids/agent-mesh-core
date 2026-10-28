"""Build A2A agents from plain async functions.

    async def handle(payload: dict, ctx: AgentContext) -> dict: ...

    app = build_agent_app(
        name="retriever", description="...", url="http://127.0.0.1:9201",
        skills=[Skill("fetch_part", "Fetch CFR part", "...")], handler=handle,
    )

Payloads travel as a JSON text part (media type application/json) rather
than an A2A data part: data parts go through protobuf Struct, which turns
every integer into a float.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from a2a.helpers import get_message_text, new_task_from_user_message, new_text_message, new_text_part
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentSkill, Message, Part, TaskState
from opentelemetry import trace
from starlette.applications import Starlette

from agentmesh.client import JSON_MEDIA, MeshClient, payload_from_parts
from agentmesh.serve import GatewayOnly, require_gateway
from agentmesh.tracing import extract_context

log = logging.getLogger(__name__)


@dataclass
class Skill:
    id: str
    name: str
    description: str
    tags: list[str] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)


@dataclass
class AgentContext:
    caller: str | None  # principal the gateway authenticated, if called through it
    task_id: str
    context_id: str
    mesh: MeshClient | None  # this agent's own credentials, for its MCP/A2A calls


Handler = Callable[[dict[str, Any], AgentContext], Awaitable[dict[str, Any]]]


def json_part(payload: Any) -> Part:
    return new_text_part(json.dumps(payload), media_type=JSON_MEDIA)


class FunctionExecutor(AgentExecutor):
    def __init__(self, handler: Handler, mesh: MeshClient | None, name: str = "agent"):
        self.handler = handler
        self.mesh = mesh
        self.name = name

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        task = context.current_task
        if task is None:
            task = new_task_from_user_message(context.message)
            await event_queue.enqueue_event(task)
        updater = TaskUpdater(event_queue=event_queue, task_id=task.id, context_id=task.context_id)
        await updater.update_status(state=TaskState.TASK_STATE_WORKING)

        headers = context.call_context.state.get("headers", {}) if context.call_context else {}
        ctx = AgentContext(caller=headers.get("x-agentmesh-principal"), task_id=task.id,
                           context_id=task.context_id, mesh=self.mesh)
        # continue the caller's trace so this agent's MCP/A2A calls join it
        span = trace.get_tracer("agentmesh.agent").start_as_current_span(
            f"agent.{self.name}", context=extract_context(headers), kind=trace.SpanKind.SERVER,
            attributes={"mesh.caller": ctx.caller or "", "a2a.task_id": task.id})
        try:
            with span:
                result = await self.handler(payload_from_parts(context.message.parts), ctx)
        except Exception as exc:  # report the failure to the caller instead of a bare 500
            log.exception("handler failed")
            await updater.update_status(
                state=TaskState.TASK_STATE_FAILED,
                message=new_text_message(f"{exc.__class__.__name__}: {exc}",
                                         context_id=task.context_id, task_id=task.id),
            )
            return
        await updater.add_artifact(parts=[json_part(result)], name="result")
        await updater.update_status(state=TaskState.TASK_STATE_COMPLETED)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError("cancel is not supported")


def build_agent_card(name: str, description: str, url: str, skills: list[Skill],
                     version: str = "0.1.0") -> AgentCard:
    return AgentCard(
        name=name,
        description=description,
        version=version,
        default_input_modes=[JSON_MEDIA, "text/plain"],
        default_output_modes=[JSON_MEDIA],
        capabilities=AgentCapabilities(streaming=True),
        supported_interfaces=[AgentInterface(protocol_binding="JSONRPC", url=url, protocol_version="1.0")],
        skills=[AgentSkill(id=s.id, name=s.name, description=s.description, tags=s.tags,
                           examples=s.examples) for s in skills],
    )


def build_agent_app(*, name: str, description: str, url: str, skills: list[Skill], handler: Handler,
                    mesh: MeshClient | None = None, version: str = "0.1.0") -> GatewayOnly:

    card = build_agent_card(name, description, url, skills, version)
    request_handler = DefaultRequestHandler(
        agent_executor=FunctionExecutor(handler, mesh, name),
        task_store=InMemoryTaskStore(),
        agent_card=card,
    )
    routes = [*create_agent_card_routes(card), *create_jsonrpc_routes(request_handler, "/")]
    return require_gateway(Starlette(routes=routes))


def message_text(message: Message) -> str:
    return get_message_text(message)
