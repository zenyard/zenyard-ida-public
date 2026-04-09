import json
import typing as ty

from langchain.agents.middleware import AgentMiddleware, AgentState
from langchain.agents.middleware.types import ToolCallRequest
from langchain_core.messages import AIMessage, HumanMessage

from decompai_ida import logger
from decompai_ida.copilot_prompts import (
    loop_guard_force_response_hint,
    loop_guard_pivot_escalation_hint,
    loop_guard_pivot_hint,
)
from decompai_ida.copilot_runtime import (
    CopilotRuntimeConfig,
    is_transient_provider_error,
)


class CopilotMiddlewareState(AgentState):
    last_tool_batch_signature: str
    same_tool_batch_count: int
    loop_guard_pivot_count: int


def loop_guard_state_reset() -> dict[str, ty.Any]:
    """Reset fields when a new user message starts a copilot turn (see copilot_task)."""
    return {
        "last_tool_batch_signature": "",
        "same_tool_batch_count": 0,
        "loop_guard_pivot_count": 0,
    }


class CopilotLoopGuardMiddleware(AgentMiddleware):
    state_schema = CopilotMiddlewareState

    def __init__(self, runtime_config: CopilotRuntimeConfig):
        self._runtime_config = runtime_config

    def before_model(
        self,
        state: AgentState[ty.Any],
        runtime,  # noqa: ANN001 - middleware interface
    ) -> ty.Optional[dict[str, ty.Any]]:
        last_ai_tool_message = _get_last_ai_tool_message(
            state.get("messages", [])
        )
        if last_ai_tool_message is None:
            return None

        tool_batch_signature = build_tool_batch_signature(last_ai_tool_message)
        tool_category_signature = build_tool_category_signature(
            last_ai_tool_message
        )
        previous_signature = state.get("last_tool_batch_signature", "")
        previous_count = state.get("same_tool_batch_count", 0)
        repeat_count = (
            previous_count + 1
            if tool_batch_signature == previous_signature
            else 1
        )
        pivot_count = state.get("loop_guard_pivot_count", 0)

        update: dict[str, ty.Any] = {
            "last_tool_batch_signature": tool_batch_signature,
            "same_tool_batch_count": repeat_count,
            "loop_guard_pivot_count": pivot_count,
        }

        if (
            _message_contains_tool_name(last_ai_tool_message, "write_todos")
            and repeat_count >= self._runtime_config.repeated_todo_limit
        ):
            update["messages"] = [
                HumanMessage(
                    loop_guard_force_response_hint(tool_category_signature)
                )
            ]
            return update

        if repeat_count == self._runtime_config.repeated_tool_batch_limit:
            if (
                pivot_count
                >= self._runtime_config.loop_guard_pivot_escalation_after
            ):
                pivot_body = loop_guard_pivot_escalation_hint(
                    tool_category_signature
                )
            else:
                pivot_body = loop_guard_pivot_hint(tool_category_signature)
            update["messages"] = [HumanMessage(pivot_body)]
            update["loop_guard_pivot_count"] = pivot_count + 1
            return update

        if repeat_count > self._runtime_config.repeated_tool_batch_limit:
            update["messages"] = [
                HumanMessage(
                    loop_guard_force_response_hint(tool_category_signature)
                )
            ]
            return update

        return update


class CopilotDelegatedTaskRetryMiddleware(AgentMiddleware):
    def __init__(self, runtime_config: CopilotRuntimeConfig):
        self._retry_limit = runtime_config.delegated_task_retry_limit

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler,
    ):
        attempt = 0
        while True:
            try:
                return handler(request)
            except Exception as ex:
                if not self._should_retry(request, ex, attempt):
                    raise
                attempt += 1
                logger.warning(
                    "Retrying delegated task tool after transient provider error",
                    attempt=attempt,
                    retry_limit=self._retry_limit,
                    error=str(ex),
                )

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler,
    ):
        attempt = 0
        while True:
            try:
                return await handler(request)
            except Exception as ex:
                if not self._should_retry(request, ex, attempt):
                    raise
                attempt += 1
                logger.warning(
                    "Retrying delegated task tool after transient provider error",
                    attempt=attempt,
                    retry_limit=self._retry_limit,
                    error=str(ex),
                )

    def _should_retry(
        self,
        request: ToolCallRequest,
        exception: Exception,
        attempt: int,
    ) -> bool:
        return (
            self._retry_limit > attempt
            and request.tool_call.get("name", "") == "task"
            and is_transient_provider_error(exception)
        )


def build_tool_batch_signature(message: AIMessage) -> str:
    return ",".join(
        _format_tool_call_signature(tool_call)
        for tool_call in message.tool_calls
    )


def build_tool_category_signature(message: AIMessage) -> str:
    return ",".join(
        _tool_call_name(tool_call) for tool_call in message.tool_calls
    )


def _get_last_ai_tool_message(messages: list[ty.Any]) -> ty.Optional[AIMessage]:
    for message in reversed(messages):
        if isinstance(message, AIMessage) and message.tool_calls:
            return message
    return None


def _format_tool_call_signature(tool_call: ty.Any) -> str:
    name = _tool_call_name(tool_call)
    args = json.dumps(_tool_call_args(tool_call), sort_keys=True, default=str)
    return f"{name}#{hash(args)}"


def _tool_call_name(tool_call: ty.Any) -> str:
    return str(
        getattr(tool_call, "get", lambda *_args, **_kwargs: "")("name", "")
    ).strip()


def _tool_call_args(tool_call: ty.Any) -> dict[str, ty.Any]:
    args = getattr(tool_call, "get", lambda *_args, **_kwargs: {})("args", {})
    return args if isinstance(args, dict) else {}


def _message_contains_tool_name(message: AIMessage, tool_name: str) -> bool:
    return any(
        _tool_call_name(tool_call) == tool_name
        for tool_call in message.tool_calls
    )
