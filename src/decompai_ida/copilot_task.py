import copy
import typing as ty

from decompai_ida import logger
from decompai_ida.model import Message
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
from langchain.agents import create_agent
from langchain.agents.middleware import (
    SummarizationMiddleware,
    ToolRetryMiddleware,
)
from langchain_core.messages.human import HumanMessage
from langchain_core.rate_limiters import InMemoryRateLimiter
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.pregel import Pregel


AGENT_SYSTEM_PROMPT = """
You are a reverse engineering AI assistant. Your name is "Zenyard Copilot".

You run inside IDA (Interactive DisAssembler); you have tools to extract information and make changes to the currently opened file.

You accomplish a given task iteratively, breaking it down into clear steps and working through them methodically. The general workflow is:

1. Clearly understand the task and plan clear, achievable goals to accomplish it. Prioritize these goals in a logical order.
2. Use tools to collect required information to achieve your goals. List most important findings and modify your plan if new information contradicts your existing plan. Repeat until you have the information you need to achieve your goals, or until you have no clear way to collect remaining information.
3. Give clear and detailed response to the question asked (if any); if asked for modifications, give summary of changes you will make (only a few examples if many).
4. If asked for modifications, perform these in bulk.

Rules:

- At steps #2 and #4, perform as many tool calls as you know are necessary. For tools with paginated outputs, don't request more than one page in a single turn (good: invoking different tools with paginated outputs, or same tool with different filtering parameters; bad: same tool with same filtering parameters but for different pages); use your next turn to ask for next page if necessary.
- The user may provide feedback, which you can use to make improvements and try again. But DO NOT continue in pointless back and forth conversations, i.e. don't end your responses with questions or offers for further assistance.
- When using paginated tools, do NOT inform the user about pagination details.
- Output markdown WITHOUT HTML tags (e.g. NO `<br>` tags). If some output requires HTML to be properly formatted, ALWAYS fall back to closest non-HTML markdown formatting.
- When about to call tools, end your text with period, not colon.
""".strip()

# Shown before first tokens
_STARTING_RESPONSE_PLACEHOLDER = "●"

# Summarization configuration
TOKENS_THRESHOLD_FOR_SUMMARIZATION = 150_000
SUMMARIZATION_MAX_TOKENS = 10_000

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
                    copilot_model.notify_update()
            else:
                await copilot_model.wait_for_update()

    async def _handle_user_message(self, agent: Pregel, user_message: Message):
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
        copilot_model.notify_update()

        try:
            async for (
                message_chunk,
                message_metadata,
            ) in agent.astream(
                {"messages": [HumanMessage(content=user_message.text)]},
                config,
                stream_mode="messages",
            ):
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

                if copilot_model.stop_requested:
                    await logger.ainfo("Stop requested by user")
                    break
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
        llm_for_summarization = init_chat_model(
            copilot_config.model_name,
            model_provider=copilot_config.model_provider,
            rate_limiter=InMemoryRateLimiter(requests_per_second=15 / 60),
            **additional_params,
            **computed_additional_params,
        ).bind(max_tokens=SUMMARIZATION_MAX_TOKENS)

        summarization_middleware = SummarizationMiddleware(
            model=llm_for_summarization,
            trigger=("tokens", TOKENS_THRESHOLD_FOR_SUMMARIZATION),
        )

        # Handle tool errors gracefully by converting exceptions to error messages
        tool_error_handler = ToolRetryMiddleware(
            max_retries=0,  # Don't retry, just catch and handle errors
            on_failure="continue",  # Continue execution instead of raising
        )

        return create_agent(
            llm,
            tools,
            system_prompt=AGENT_SYSTEM_PROMPT,
            checkpointer=checkpointer,
            middleware=[tool_error_handler, summarization_middleware],
            debug=self._ctx.plugin_config.log_level == "DEBUG",
        )


def exception_to_user_message(exception: Exception) -> str:
    """
    Translate an exception into a user-facing error message for the copilot chat.
    """
    if _is_rate_limit_Error(exception):
        return "This request was rate-limited. Please try again soon."

    return (
        "I encountered an error while processing your request. "
        "Please try again or rephrase your question."
    )


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
