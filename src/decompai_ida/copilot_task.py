import copy
import typing as ty

from decompai_ida import logger
from decompai_ida.model import Message
from decompai_ida.tasks import Task, TaskContext
from decompai_client.models.copilot_config import CopilotConfig
from decompai_ida.copilot_tools import get_copilot_tools

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


# TODO: Taken inspiration from Cline's system prompt.
# Either come up with a system prompt from scratch or attribute Cline (if possible with their license).
AGENT_SYSTEM_PROMPT = """
You are a reverse engineering ai assistant. Your name is "Zenyard Copilot".

You accomplish a given task iteratively, breaking it down into clear steps and working through them methodically.

1. Analyze the user's task and set clear, achievable goals to accomplish it. Prioritize these goals in a logical order.
2. Work through these goals sequentially, utilizing available tools as necessary. You are allowed and encouraged to perform multiple tool calls within a single turn to make progress in a single goal. Each goal should correspond to a distinct step in your problem-solving process. You will be informed on the work completed and what's remaining as you go.
3. The user may provide feedback, which you can use to make improvements and try again. But DO NOT continue in pointless back and forth conversations, i.e. don't end your responses with questions or offers for further assistance.
4. When using paginated tools, do NOT inform the user about pagination details.
""".strip()

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
        # Add empty AI message to start filling
        copilot_model.messages.append(Message("AI", ""))
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
                if message_metadata["langgraph_node"] == "model":
                    await logger.adebug(
                        "Received message chunk",
                        content=message_chunk.content,
                    )
                    match message_chunk.content:
                        case list():
                            for content_part in message_chunk.content:
                                copilot_model.messages[
                                    -1
                                ].text += content_part.get("text", "")
                                copilot_model.notify_update()
                        case _:
                            copilot_model.messages[
                                -1
                            ].text += message_chunk.content
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
                copilot_model.messages[-1].text = (
                    "I encountered an error while processing your request. "
                    "Please try again or rephrase your question."
                )

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
