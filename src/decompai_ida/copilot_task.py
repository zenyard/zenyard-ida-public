from dataclasses import dataclass
import typing as ty
import uuid

import typing_extensions as tye
from deepagents import create_deep_agent
from deepagents.middleware.subagents import SubAgent
from langchain.agents.middleware import ToolRetryMiddleware
from langchain_core.messages import AIMessageChunk
from langchain_core.messages.human import HumanMessage
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph.state import CompiledStateGraph

from decompai_client.models import (
    CopilotClearRequestedEvent,
    CopilotMessageSentEvent,
    CopilotStopRequestedEvent,
)
from decompai_client.models.copilot_config import CopilotConfig
from decompai_ida import logger
from decompai_ida.analytics_task import analytics_timestamp
from decompai_ida.copilot_middleware import (
    CopilotDelegatedTaskRetryMiddleware,
    CopilotLoopGuardMiddleware,
    loop_guard_state_reset,
)
from decompai_ida.copilot_prompts import (
    CRITIC_SUBAGENT_PROMPT,
    EXPLORE_SUBAGENT_PROMPT,
    RESEARCHER_SUBAGENT_PROMPT,
    TOOLRUNNER_SUBAGENT_PROMPT,
    build_system_prompt,
)
from decompai_ida.copilot_runtime import (
    CopilotRuntimeConfig,
    create_chat_model,
    exception_to_user_message,
)
from decompai_ida.copilot_session_notes import append_session_entry
from decompai_ida.copilot_tools import CopilotTools, get_copilot_tools
from decompai_ida.model import CopilotModel, Message, Task as TodoTask
from decompai_ida.tasks import Task, TaskContext


# Shown before first tokens
_STARTING_RESPONSE_PLACEHOLDER = "●"

COPILOT_THREAD_ID = "1"


@dataclass(frozen=True)
class _CopilotAttemptResult:
    final_text: str
    completed_todos: list[str]
    exception: ty.Optional[Exception] = None


class CopilotTask(Task):
    def __init__(self, task_context: TaskContext):
        super().__init__(task_context)
        self._message_index: int = 0
        self._analytics_thread_id: str = ""
        self._copilot_config: ty.Optional[CopilotConfig] = None
        self._runtime_config: ty.Optional[CopilotRuntimeConfig] = None
        self._checkpointer: ty.Optional[InMemorySaver] = None
        self._agent: ty.Optional[CompiledStateGraph] = None
        self._agent_session_notes: ty.Optional[str] = None

    async def _run(self) -> None:
        user_config = await self._ctx.model.wait_for_user_config()
        if user_config.copilot is None:
            return
        self._copilot_config = user_config.copilot
        self._runtime_config = CopilotRuntimeConfig.from_copilot_config(
            user_config.copilot
        )
        self._checkpointer = InMemorySaver()
        self._analytics_thread_id = str(uuid.uuid4())
        await self._run_copilot()

    async def _run_copilot(self) -> None:
        copilot_model = self._ctx.copilot_model
        checkpointer = self._require_checkpointer()

        while True:
            if copilot_model.clear_requested:
                copilot_model.clear_requested = False
                copilot_model.messages.clear()
                copilot_model.tasks = []
                await checkpointer.adelete_thread(COPILOT_THREAD_ID)
                await self._emit_clear_analytic()
                copilot_model.notify_update()
                continue

            if (
                copilot_model.messages
                and copilot_model.messages[-1].sender == "User"
            ):
                user_message = copilot_model.messages[-1]
                try:
                    await self._emit_message_sent_analytic(user_message)
                    (
                        response_text,
                        completed_todos,
                    ) = await self._handle_user_message(user_message)
                    await self._append_session_notes(
                        self._require_runtime_config(),
                        user_message=user_message.text,
                        response_text=response_text,
                        completed_todos=completed_todos,
                    )
                finally:
                    copilot_model.is_active = False
                    copilot_model.stop_requested = False
                    copilot_model.tasks = []
                    copilot_model.notify_update()
            else:
                await copilot_model.wait_for_update()

    async def _handle_user_message(
        self,
        user_message: Message,
    ) -> tuple[str, list[str]]:
        copilot_model = self._ctx.copilot_model
        copilot_model.messages.append(
            Message("AI", _STARTING_RESPONSE_PLACEHOLDER)
        )
        copilot_model.is_active = True
        copilot_model.tasks = []
        copilot_model.notify_update()

        result = await self._stream_user_message_attempt(user_message)
        if result.exception is None:
            return result.final_text, result.completed_todos

        _set_error_on_current_ai_message(
            copilot_model,
            exception_to_user_message(result.exception),
        )
        return "", []

    async def _stream_user_message_attempt(
        self,
        user_message: Message,
    ) -> _CopilotAttemptResult:
        await self._ensure_agent()
        agent = self._require_agent()
        runtime_config = self._require_runtime_config()

        config: RunnableConfig = {
            "configurable": {"thread_id": COPILOT_THREAD_ID},
            "recursion_limit": runtime_config.recursion_limit,
        }

        copilot_model = self._ctx.copilot_model
        last_message_id: ty.Optional[str] = None
        tool_call_ids = set[str]()
        try:
            async for event in agent.astream(
                {
                    "messages": [HumanMessage(content=user_message.text)],
                    **loop_guard_state_reset(),
                },
                config,
                stream_mode=["messages", "updates"],
                subgraphs=True,
            ):
                if copilot_model.stop_requested:
                    await logger.ainfo("Stop requested by user")
                    await self._emit_stop_analytic()
                    break

                namespace, mode, data = event

                if mode == "updates" and isinstance(data, dict):
                    for _node_name, node_output in data.items():
                        if (
                            isinstance(node_output, dict)
                            and (todos := node_output.get("todos")) is not None
                        ):
                            copilot_model.tasks = [
                                _todo_from_update(todo) for todo in todos
                            ]
                            copilot_model.notify_update()
                    continue

                # Only show root-agent text to user; still track subagent tool calls.
                if namespace:
                    if mode == "messages":
                        message_chunk, _ = data
                        if isinstance(message_chunk, AIMessageChunk):
                            tool_call_ids.update(
                                tool_chunk["id"]
                                for tool_chunk in message_chunk.tool_call_chunks
                                if "id" in tool_chunk
                                and tool_chunk["id"] is not None
                            )
                            copilot_model.messages[-1].tool_count = len(
                                tool_call_ids
                            )
                            if message_chunk.tool_call_chunks:
                                copilot_model.notify_update()
                    continue

                message_chunk, message_metadata = data

                if isinstance(message_metadata, str) or isinstance(
                    message_chunk, str
                ):
                    continue

                await logger.adebug(
                    "Received message chunk",
                    chunk=message_chunk,
                )

                if isinstance(message_chunk, AIMessageChunk):
                    if (
                        message_chunk.text
                        and copilot_model.messages[-1].text
                        == _STARTING_RESPONSE_PLACEHOLDER
                    ):
                        copilot_model.messages[-1].text = ""

                    if message_chunk.id is not None:
                        if (
                            last_message_id is not None
                            and last_message_id != message_chunk.id
                        ):
                            copilot_model.messages[-1].text += "\n\n"
                        last_message_id = message_chunk.id

                    copilot_model.messages[-1].text += message_chunk.text

                    tool_call_ids.update(
                        tool_chunk["id"]
                        for tool_chunk in message_chunk.tool_call_chunks
                        if "id" in tool_chunk and tool_chunk["id"] is not None
                    )
                    copilot_model.messages[-1].tool_count = len(tool_call_ids)

                    copilot_model.notify_update()

        except Exception as ex:
            await logger.aerror(f"Error during agent streaming: {ex}")
            return _CopilotAttemptResult(
                final_text=_current_ai_text(copilot_model),
                completed_todos=_completed_todos(copilot_model),
                exception=ex,
            )

        if copilot_model.stop_requested:
            return _CopilotAttemptResult(
                final_text="",
                completed_todos=[],
            )

        final_text = _current_ai_text(copilot_model)
        return _CopilotAttemptResult(
            final_text=final_text,
            completed_todos=_completed_todos(copilot_model),
        )

    async def _emit_message_sent_analytic(self, message: Message) -> None:
        event = CopilotMessageSentEvent(
            timestamp=analytics_timestamp(),
            input_length_chars=len(message.text),
            thread_id=self._analytics_thread_id,
            message_index=self._message_index,
        )
        self._message_index += 1
        self._ctx.emit_analytics_event(event)

    async def _emit_stop_analytic(self) -> None:
        self._ctx.emit_analytics_event(
            CopilotStopRequestedEvent(timestamp=analytics_timestamp())
        )

    async def _emit_clear_analytic(self) -> None:
        self._message_index = 0
        self._analytics_thread_id = str(uuid.uuid4())
        self._ctx.emit_analytics_event(
            CopilotClearRequestedEvent(timestamp=analytics_timestamp())
        )

    async def _ensure_agent(self) -> None:
        session_notes = await self._ctx.model.copilot_session_notes.get()
        if (
            self._agent is not None
            and self._agent_session_notes == session_notes
        ):
            return

        copilot_config = self._require_copilot_config()
        runtime_config = self._require_runtime_config()
        checkpointer = self._require_checkpointer()

        await logger.ainfo(
            "Initializing copilot with configuration",
            model_name=copilot_config.model_name,
            model_provider=copilot_config.model_provider,
        )
        llm = create_chat_model(
            copilot_config,
            plugin_api_key=self._ctx.plugin_config.api_key,
        )
        tools = await get_copilot_tools(self._ctx.model)

        tool_error_handler = ToolRetryMiddleware(
            max_retries=0,
            on_failure="continue",
        )
        middleware = [
            tool_error_handler,
            CopilotDelegatedTaskRetryMiddleware(runtime_config),
            CopilotLoopGuardMiddleware(runtime_config),
        ]

        self._agent = create_deep_agent(
            model=llm,
            tools=tools.all_tools(),
            system_prompt=build_system_prompt(session_notes=session_notes),
            checkpointer=checkpointer,
            middleware=middleware,
            subagents=_build_subagents(tools, tool_error_handler),  # type: ignore
            debug=self._ctx.plugin_config.log_level == "DEBUG",
        )
        self._agent_session_notes = session_notes

    async def _append_session_notes(
        self,
        runtime_config: CopilotRuntimeConfig,
        *,
        user_message: str,
        response_text: str,
        completed_todos: list[str],
    ) -> None:
        if not response_text.strip() and not completed_todos:
            return
        existing_notes = await self._ctx.model.copilot_session_notes.get()
        updated_notes = append_session_entry(
            existing_notes,
            user_query=user_message,
            completed_todos=completed_todos,
            response_snippet=response_text,
            max_chars=runtime_config.session_notes_max_chars,
        )
        await self._ctx.model.copilot_session_notes.set(updated_notes)

    def _require_copilot_config(self) -> CopilotConfig:
        if self._copilot_config is None:
            raise RuntimeError("Copilot config is not initialized.")
        return self._copilot_config

    def _require_runtime_config(self) -> CopilotRuntimeConfig:
        if self._runtime_config is None:
            raise RuntimeError("Copilot runtime config is not initialized.")
        return self._runtime_config

    def _require_checkpointer(self) -> InMemorySaver:
        if self._checkpointer is None:
            raise RuntimeError("Copilot checkpointer is not initialized.")
        return self._checkpointer

    def _require_agent(self) -> CompiledStateGraph:
        if self._agent is None:
            raise RuntimeError("Copilot agent is not initialized.")
        return self._agent


def _build_subagents(
    tools: CopilotTools,
    tool_error_handler: ToolRetryMiddleware,
) -> list[SubAgent]:
    read_tools = tools.common + tools.exploration
    return [
        SubAgent(  # type: ignore
            name="explore",
            description=(
                "Focused read-only exploration of the IDA database. Use for "
                "call chains, xrefs, strings, types, comments, and symbols."
            ),
            system_prompt=EXPLORE_SUBAGENT_PROMPT,
            tools=read_tools,
            middleware=[tool_error_handler],
        ),
        SubAgent(  # type: ignore
            name="researcher",
            description=(
                "Deep evidence gathering and synthesis for harder reverse "
                "engineering questions."
            ),
            system_prompt=RESEARCHER_SUBAGENT_PROMPT,
            tools=read_tools,
            middleware=[tool_error_handler],
        ),
        SubAgent(  # type: ignore
            name="critic",
            description=(
                "Reviews the current plan or interpretation for gaps, risks, "
                "and missing validation."
            ),
            system_prompt=CRITIC_SUBAGENT_PROMPT,
            tools=read_tools,
            middleware=[tool_error_handler],
        ),
        SubAgent(  # type: ignore
            name="toolrunner",
            description=(
                "Execution-focused analysis helper that proposes and performs "
                "the best next read-only tool calls."
            ),
            system_prompt=TOOLRUNNER_SUBAGENT_PROMPT,
            tools=read_tools,
            middleware=[tool_error_handler],
        ),
    ]


def _todo_from_update(todo: dict[str, ty.Any]) -> TodoTask:
    status = str(todo.get("status", "pending"))
    if status not in {"pending", "in_progress", "completed"}:
        status = "pending"
    normalized_status = ty.cast(
        tye.Literal["pending", "in_progress", "completed"], status
    )
    return TodoTask(
        content=str(todo.get("content", "")), status=normalized_status
    )


def _completed_todos(copilot_model: CopilotModel) -> list[str]:
    return [
        task.content
        for task in copilot_model.tasks
        if task.status == "completed"
    ]


def _current_ai_text(copilot_model: CopilotModel) -> str:
    if not copilot_model.messages or copilot_model.messages[-1].sender != "AI":
        return ""
    final_text = copilot_model.messages[-1].text
    if final_text == _STARTING_RESPONSE_PLACEHOLDER:
        final_text = ""
        copilot_model.messages[-1].text = ""
    return final_text


def _set_error_on_current_ai_message(
    copilot_model: CopilotModel, error_text: str
) -> None:
    if not copilot_model.messages or copilot_model.messages[-1].sender != "AI":
        return
    if copilot_model.messages[-1].text == _STARTING_RESPONSE_PLACEHOLDER:
        copilot_model.messages[-1].text = ""
    if copilot_model.messages[-1].text:
        copilot_model.messages[-1].text += "\n\n"
    copilot_model.messages[-1].text += f"**{error_text}**"
