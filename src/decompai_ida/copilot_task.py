import copy
import typing as ty

from decompai_ida import logger
from decompai_ida.tasks import Task, TaskContext
from decompai_ida.ui.copilot import Message
from decompai_ida.summarization import SummarizationNode
from decompai_client.models.copilot_config import CopilotConfig

from langchain.chat_models import init_chat_model
from langchain_core.messages.human import HumanMessage
from langchain_core.messages.utils import count_tokens_approximately
from langchain_core.prompts.chat import ChatPromptTemplate
from langchain_core.rate_limiters import InMemoryRateLimiter
from langchain_core.runnables import RunnableConfig
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.sessions import StreamableHttpConnection
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.pregel import Pregel
from langgraph.prebuilt import create_react_agent
from langgraph.prebuilt.chat_agent_executor import AgentState


# TODO: Taken inspiration from Cline's system prompt.
# Either come up with a system prompt from scratch or attribute Cline (if possible with their license).
AGENT_SYSTEM_PROMPT = """
You are a reverse engineering ai assistant.
You accomplish a given task iteratively, breaking it down into clear steps and working through them methodically.

1. Analyze the user's task and set clear, achievable goals to accomplish it. Prioritize these goals in a logical order.
2. Work through these goals sequentially, utilizing available tools one at a time as necessary. Each goal should correspond to a distinct step in your problem-solving process. You will be informed on the work completed and what's remaining as you go.
3. The user may provide feedback, which you can use to make improvements and try again. But DO NOT continue in pointless back and forth conversations, i.e. don't end your responses with questions or offers for further assistance.
4. When using paginated tools, do NOT inform the user about pagination details.
""".strip()

INITIAL_SUMMARY_PROMPT = ChatPromptTemplate.from_messages(
    [
        ("placeholder", "{messages}"),
        (
            "user",
            """
            Create a summary of the conversation above.
            Keep the current task goals and plan, conclusions and key findings.
            If there's still an ongoing goal finish the message by instructing what to do next.
            Do not create new tasks or goals.
            Do not finish with questions or asking for further assistance.
            """,
        ),
    ]
)
DEFAULT_EXISTING_SUMMARY_PROMPT = ChatPromptTemplate.from_messages(
    [
        ("placeholder", "{messages}"),
        (
            "user",
            """
            This is summary of the conversation so far: {existing_summary}

            Extend this summary by taking into account the new messages above.
            Keep the current task goals and plan, conclusions and key findings.
            If there's still an ongoing goal finish the message by instructing what to do next.
            Always write the new summary in its entirety.
            Do not create new tasks or goals.
            Do not finish with questions or asking for further assistance.
            """,
        ),
    ]
)
SUMMARIZATION_FINAL_PROMPT = ChatPromptTemplate.from_messages(
    [
        ("placeholder", "{system_message}"),
        ("user", "Summary of the conversation so far: {summary}"),
        ("placeholder", "{messages}"),
    ]
)
TOKENS_THRESHOLD_FOR_SUMMARIZATION = 150_000
SUMMARIZATION_MAX_TOKENS = 10_000

COPILOT_THREAD_ID = "1"


class CopilotTask(Task):
    def __init__(self, task_context: TaskContext):
        super().__init__(task_context)

    async def _run(self) -> None:
        user_config = await self._retry_api_request_forever(
            lambda: self._ctx.user_api.get_user_config(),
            description="Get Copilot configuration",
        )
        if user_config is None or user_config.copilot is None:
            return
        self._ctx.copilot_model.configuration = user_config.copilot
        self._ctx.copilot_model.notify_update()

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
                if message_metadata["langgraph_node"] == "agent":
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
        # Wait for MCP server port to be set
        copilot_model = self._ctx.copilot_model
        if copilot_model.mcp_server_port is None:
            await logger.adebug("Waiting for mcp server to start")
        while copilot_model.mcp_server_port is None:
            await copilot_model.wait_for_update()
        await logger.ainfo(
            f"MCP server port received: {copilot_model.mcp_server_port}"
        )
        await logger.ainfo(
            "Initializing copilot with configuration",
            model_name=copilot_config.model_name,
            model_provider=copilot_config.model_provider,
        )
        additional_params = copy.deepcopy(copilot_config.additional_params)
        computed_additional_params = {}
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

        # Get MCP server port from copilot model
        mcp_server_port = copilot_model.mcp_server_port
        assert (
            mcp_server_port is not None
        ), "MCP server port should be available"

        ida_mcp: StreamableHttpConnection = {
            "url": f"http://localhost:{mcp_server_port}/mcp",
            "transport": "streamable_http",
        }  # type: ignore
        client = MultiServerMCPClient({"ida": ida_mcp})
        tools = await client.get_tools()
        llm_for_summarization = (
            init_chat_model(
                copilot_config.model_name,
                model_provider=copilot_config.model_provider,
                rate_limiter=InMemoryRateLimiter(requests_per_second=15 / 60),
                **additional_params,
                **computed_additional_params,
            )
            .bind_tools(
                # Bedrock throws error if summarization messages include tools without this
                tools
            )
            .bind(max_tokens=SUMMARIZATION_MAX_TOKENS)
        )

        class State(AgentState):
            # NOTE: we're adding this key to keep track of previous summary information
            # to make sure we're not summarizing on every LLM call
            context: dict[str, ty.Any]

        summarization_node = SummarizationNode(
            token_counter=count_tokens_approximately,
            model=llm_for_summarization,
            max_tokens=TOKENS_THRESHOLD_FOR_SUMMARIZATION,
            max_summary_tokens=SUMMARIZATION_MAX_TOKENS,
            output_messages_key="llm_input_messages",
            initial_summary_prompt=INITIAL_SUMMARY_PROMPT,
            existing_summary_prompt=DEFAULT_EXISTING_SUMMARY_PROMPT,
            final_prompt=SUMMARIZATION_FINAL_PROMPT,
        )

        return create_react_agent(
            llm,
            tools,
            prompt=AGENT_SYSTEM_PROMPT,
            checkpointer=checkpointer,
            pre_model_hook=summarization_node,
            state_schema=State,
            debug=self._ctx.plugin_config.log_level == "DEBUG",
        )
