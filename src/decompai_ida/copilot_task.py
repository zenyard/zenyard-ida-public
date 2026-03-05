import copy
import typing as ty

from decompai_ida import logger
from decompai_ida.model import Message, Task as TodoTask
from decompai_ida.tasks import Task, TaskContext
from decompai_client.models.copilot_config import CopilotConfig
from decompai_ida.copilot_tools import get_copilot_tools
from langchain_core.messages import AIMessageChunk

import openai
import anthropic
import botocore.exceptions
import google.api_core.exceptions
import ollama
from langchain.chat_models import init_chat_model
from deepagents import create_deep_agent
from deepagents.middleware.subagents import SubAgent
from langchain.agents.middleware import ToolRetryMiddleware
from langchain_core.messages.human import HumanMessage
from langchain_core.rate_limiters import InMemoryRateLimiter
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph.state import CompiledStateGraph


AGENT_SYSTEM_PROMPT = """
You are a reverse engineering AI assistant. Your name is "Zenyard Copilot".

You run inside IDA (Interactive DisAssembler); you have tools to extract information and make changes to the currently opened file.

## Core behavior

- Be concise and action-oriented. Lead with findings, not process.
- Prefer evidence from tools over assumptions. Never fabricate function names, addresses, or decompilation results.
- State uncertainty explicitly when tool results are ambiguous or incomplete.
- Do not end responses with questions or offers for further assistance — avoid pointless back and forth.

## Task management

- For complex or multi-step work, use `write_todos` to track goals. Keep TODOs short and concrete.
- Skip TODOs for simple, single-step requests.

## Delegation

- Delegate read-only operations (decompile, list functions, resolve addresses, search comments, browse types) using the `task()` tool.
- Choose the sub-agent role that fits the task:
  - `explore` — map relevant symbols/functions, find what to investigate next
  - `researcher` — deep analysis of a subsystem, correlating findings across multiple functions
  - `critic` — identify gaps or risky assumptions before committing to modifications
- Keep delegated tasks narrow and self-contained. Bad: "understand the whole binary". Good: "find all callers of sub_1400 and summarize what arguments they pass".
- When investigating orthogonal aspects (e.g. different functions, callers vs callees, code vs types), launch multiple tasks concurrently.

## Tool strategy

- Use parallel tool calls for independent checks.
- Cite concrete evidence (addresses, symbol names, xref counts) in your reasoning.
- Verify target symbol exists before making risky edits.
- Perform modifications (renaming, setting comments/prototypes) directly using your own tools.

## Exploration strategy

Two approaches — pick based on context and switch if stuck:

1. **Structural/call-graph**: decompile entry points, follow calls depth-first into subsystems.
2. **Breadth-first**: list functions, search comments/strings, build an overview before diving in.

Pivot rule: if the same approach yields no new information after 2–3 rounds, switch to the other. Use `search_function_comments` as a shortcut before broad exploration.

## Response style

- Start with a direct answer or summary of findings.
- Keep responses compact — avoid restating what the user already knows.
- End with clear next steps only when the task is genuinely multi-stage.
- Output markdown WITHOUT HTML tags (e.g. NO `<br>` tags).
- When about to call tools, end your text with period, not colon.
- When using paginated tools, do NOT inform the user about pagination details.
""".strip()

EXPLORE_SYSTEM_PROMPT = """
You are an IDA database exploration specialist. You read and analyze the currently opened binary.

Use your tools to fulfill the exploration task. You have access to: function listing, decompilation, caller analysis, symbol resolution, type browsing, comment searching, and Swift source (if available).

Rules:
- Check `search_function_comments` first as a quick shortcut before broad exploration.
- For paginated tools, fetch only one page per turn; request next page in your next turn if needed.
- Pivot rule: if the same tool category yields no new information after 2–3 rounds, switch to a different tool or approach.
- Return findings as structured output: separate confirmed facts from hypotheses.
- Focus only on the exploration task given; do not suggest modifications.
""".strip()


_CRITIC_SYSTEM_PROMPT = """
You are a critical reviewer for reverse engineering analysis inside IDA (Interactive DisAssembler).

Your job: identify gaps, risky assumptions, and missing validation in a plan or interpretation.

- List concrete improvements, highest-impact first.
- Use tool results as evidence; do not critique based on assumptions.
- Be direct — flag real risks, not hypothetical ones.
- Do not suggest modifications to the binary; focus on analysis quality.
""".strip()

_RESEARCHER_SYSTEM_PROMPT = """
You are a deep research specialist inside IDA (Interactive DisAssembler).

Your job: build a comprehensive, evidence-grounded picture of a subsystem or behavior.

- Separate confirmed facts (from tool output) from hypotheses (inferred).
- Correlate findings across multiple functions, types, and xrefs.
- Prioritize depth over breadth — follow the most promising leads fully.
- Return structured findings, not raw tool dumps.
- Do not suggest modifications; focus on understanding.
""".strip()


# Shown before first tokens
_STARTING_RESPONSE_PLACEHOLDER = "●"

COPILOT_THREAD_ID = "1"


class CopilotTask(Task):
    def __init__(self, task_context: TaskContext):
        super().__init__(task_context)

    async def _run(self) -> None:
        user_config = await self._ctx.model.wait_for_user_config()
        if user_config.copilot is None:
            return
        await self._run_copilot(user_config.copilot)

    async def _run_copilot(self, copilot_config: CopilotConfig) -> None:
        checkpointer = InMemorySaver()

        copilot_model = self._ctx.copilot_model
        agent = await self._create_agent(copilot_config, checkpointer)

        # Main loop: wait for updates and process messages
        while True:
            if copilot_model.clear_requested:
                copilot_model.clear_requested = False
                copilot_model.messages.clear()
                await checkpointer.adelete_thread(COPILOT_THREAD_ID)
                copilot_model.notify_update()
                continue

            # Check if there's a new message from user to process
            if (
                copilot_model.messages
                and copilot_model.messages[-1].sender == "User"
            ):
                try:
                    user_message = copilot_model.messages[-1]
                    await self._handle_user_message(agent, user_message)
                finally:
                    copilot_model.is_active = False
                    copilot_model.stop_requested = False
                    copilot_model.tasks = []
                    copilot_model.notify_update()
            else:
                await copilot_model.wait_for_update()

    async def _handle_user_message(
        self, agent: CompiledStateGraph, user_message: Message
    ):
        config: RunnableConfig = {
            "configurable": {"thread_id": COPILOT_THREAD_ID},
            "recursion_limit": 300,
        }

        copilot_model = self._ctx.copilot_model

        # Track message ID to add spaces when new message starts.
        last_message_id: ty.Optional[str] = None

        # Track tool calls across chunks
        tool_call_ids = set[str]()

        # Add empty AI message to start filling
        copilot_model.messages.append(
            Message("AI", _STARTING_RESPONSE_PLACEHOLDER)
        )
        copilot_model.is_active = True
        copilot_model.tasks = []
        copilot_model.notify_update()

        try:
            async for event in agent.astream(
                {"messages": [HumanMessage(content=user_message.text)]},
                config,
                stream_mode=["messages", "updates"],
                subgraphs=True,
            ):
                if copilot_model.stop_requested:
                    await logger.ainfo("Stop requested by user")
                    break

                namespace, mode, data = event

                if mode == "updates" and isinstance(data, dict):
                    for _node_name, node_output in data.items():
                        if (
                            isinstance(node_output, dict)
                            and (todos := node_output.get("todos")) is not None
                        ):
                            copilot_model.tasks = [
                                TodoTask(
                                    content=todo["content"],
                                    status=todo["status"],
                                )
                                for todo in todos
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

                # mode == "messages"
                message_chunk, message_metadata = data

                # Did not see this happening, ignore such message chunks
                if isinstance(message_metadata, str) or isinstance(
                    message_chunk, str
                ):
                    continue

                await logger.adebug(
                    "Received message chunk",
                    chunk=message_chunk,
                )

                if isinstance(message_chunk, AIMessageChunk):
                    # Clear placeholder
                    if (
                        message_chunk.text
                        and copilot_model.messages[-1].text
                        == _STARTING_RESPONSE_PLACEHOLDER
                    ):
                        copilot_model.messages[-1].text = ""

                    # New paragraph if this is a new message (after tool calls).
                    if message_chunk.id is not None:
                        if (
                            last_message_id is not None
                            and last_message_id != message_chunk.id
                        ):
                            copilot_model.messages[-1].text += "\n\n"
                        last_message_id = message_chunk.id

                    # Add text
                    copilot_model.messages[-1].text += message_chunk.text

                    # Count tool calls
                    tool_call_ids.update(
                        tool_chunk["id"]
                        for tool_chunk in message_chunk.tool_call_chunks
                        if "id" in tool_chunk and tool_chunk["id"] is not None
                    )
                    copilot_model.messages[-1].tool_count = len(tool_call_ids)

                    copilot_model.notify_update()
        except Exception as e:
            await logger.aerror(f"Error during agent streaming: {e}")

            # Add error message to chat to inform user
            if (
                copilot_model.messages
                and copilot_model.messages[-1].sender == "AI"
            ):
                # Replace the empty AI message with an error message
                if (
                    copilot_model.messages[-1].text
                    == _STARTING_RESPONSE_PLACEHOLDER
                ):
                    copilot_model.messages[-1].text = ""

                if copilot_model.messages[-1].text:
                    copilot_model.messages[-1].text += "\n\n"

                text_for_user = exception_to_user_message(e)
                copilot_model.messages[-1].text += f"**{text_for_user}**"

    async def _create_agent(
        self, copilot_config: CopilotConfig, checkpointer: InMemorySaver
    ):
        await logger.ainfo(
            "Initializing copilot with configuration",
            model_name=copilot_config.model_name,
            model_provider=copilot_config.model_provider,
        )
        additional_params = copy.deepcopy(copilot_config.additional_params)

        # Use user's API key if not already given in config.
        if "api_key" not in additional_params:
            additional_params["api_key"] = self._ctx.plugin_config.api_key

        computed_additional_params: dict[str, ty.Any] = {}
        if copilot_config.model_provider == "openai":
            import httpx

            if not additional_params.pop("trust_env", True):
                computed_additional_params["http_client"] = httpx.Client(
                    trust_env=False
                )
                computed_additional_params["http_async_client"] = (
                    httpx.AsyncClient(trust_env=False)
                )
        if copilot_config.model_provider == "google_anthropic_vertex":
            credentials_data = additional_params.pop("credentials")
            from google.oauth2 import service_account

            credentials = service_account.Credentials.from_service_account_info(
                credentials_data,
                scopes=[
                    "https://www.googleapis.com/auth/cloud-platform.read-only"
                ],
            )
            computed_additional_params["credentials"] = credentials
        if "max_retries" not in additional_params:
            additional_params["max_retries"] = 4
        llm = init_chat_model(
            copilot_config.model_name,
            model_provider=copilot_config.model_provider,
            rate_limiter=InMemoryRateLimiter(requests_per_second=15 / 60),
            **additional_params,
            **computed_additional_params,
        )
        tools = await get_copilot_tools(self._ctx.model)

        # Handle tool errors gracefully by converting exceptions to error messages
        tool_error_handler = ToolRetryMiddleware(
            max_retries=0,  # Don't retry, just catch and handle errors
            on_failure="continue",  # Continue execution instead of raising
        )

        explore_subagent: SubAgent = {  # type: ignore
            "name": "explore",
            "description": (
                "Map relevant symbols and functions to inspect next. Use for initial orientation: "
                "finding what exists, listing functions, resolving symbol addresses, "
                "and building a prioritized investigation path. "
                "Use multiple explore agents concurrently when investigating orthogonal aspects."
            ),
            "system_prompt": EXPLORE_SYSTEM_PROMPT,
            "tools": tools.exploration + tools.common,
            "middleware": [tool_error_handler],
        }

        researcher_subagent: SubAgent = {  # type: ignore
            "name": "researcher",
            "description": (
                "Deep research and evidence gathering. Use for thorough analysis of subsystems, "
                "correlating findings across multiple functions, or building a comprehensive "
                "picture of behavior."
            ),
            "system_prompt": _RESEARCHER_SYSTEM_PROMPT,
            "tools": tools.exploration + tools.common,
            "middleware": [tool_error_handler],
        }

        critic_subagent: SubAgent = {  # type: ignore
            "name": "critic",
            "description": (
                "Critique a plan or interpretation. Use to identify gaps, risky assumptions, "
                "or missing validation before committing to modifications."
            ),
            "system_prompt": _CRITIC_SYSTEM_PROMPT,
            "tools": tools.exploration + tools.common,
            "middleware": [tool_error_handler],
        }

        return create_deep_agent(
            model=llm,
            tools=tools.modification + tools.exploration + tools.common,
            system_prompt=AGENT_SYSTEM_PROMPT,
            checkpointer=checkpointer,
            middleware=[tool_error_handler],
            subagents=[  # type: ignore
                explore_subagent,
                researcher_subagent,
                critic_subagent,
            ],
            debug=self._ctx.plugin_config.log_level == "DEBUG",
        )


def exception_to_user_message(exception: Exception) -> str:
    """
    Translate an exception into a user-facing error message for the copilot chat.
    """
    # Join the list into a single string
    if _is_rate_limit_Error(exception):
        return "This request was rate-limited. Please try again soon."
    if _is_quota_exceeded(exception):
        return "User's quota exhausted. Upgrade or Contact us to continue."
    return (
        "I encountered an error while processing your request. "
        "Please try again or rephrase your question."
    )


def _is_quota_exceeded(exception: Exception):
    if str(getattr(exception, "status_code", "")) == "402":
        return True
    return False


def _is_rate_limit_Error(exception: Exception) -> bool:
    if isinstance(
        exception,
        (
            google.api_core.exceptions.TooManyRequests,
            google.api_core.exceptions.ResourceExhausted,
            openai.RateLimitError,
            anthropic.RateLimitError,
        ),
    ):
        return True

    if (
        isinstance(exception, botocore.exceptions.ClientError)
        and exception.response.get("Error", {}).get("Code")
        == "ThrottlingException"
    ):
        return True

    if (
        isinstance(exception, ollama.ResponseError)
        and exception.status_code == 429
    ):
        return True

    # Fallback heuristic for other providers
    exception_str = str(exception).lower()
    if "rate" in exception_str and "limit" in exception_str:
        return True

    return False
