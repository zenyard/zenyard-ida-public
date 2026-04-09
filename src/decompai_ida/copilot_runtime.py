import copy
from dataclasses import dataclass
import typing as ty

import anthropic
import botocore.exceptions
import google.api_core.exceptions
import httpx
import ollama
import openai
from langchain.chat_models import init_chat_model
from langchain_core.rate_limiters import InMemoryRateLimiter

from decompai_client.models.copilot_config import CopilotConfig

# Lower bounds applied in `from_copilot_config` when reading user settings.
MIN_RECURSION_LIMIT = 1
MIN_REPEATED_TOOL_BATCH_LIMIT = 2
MIN_REPEATED_TODO_LIMIT = 2
MIN_DELEGATED_TASK_RETRY_LIMIT = 0
MIN_SESSION_NOTES_CHARS = 1000
MIN_LOOP_GUARD_PIVOT_ESCALATION_AFTER = 1


@dataclass(frozen=True)
class CopilotRuntimeConfig:
    recursion_limit: int = 1000
    repeated_tool_batch_limit: int = 3
    repeated_todo_limit: int = 2
    delegated_task_retry_limit: int = 1
    session_notes_max_chars: int = 6000
    # After this many loop-guard pivots in a turn, use escalation copy.
    loop_guard_pivot_escalation_after: int = 2

    @classmethod
    def from_copilot_config(
        cls, copilot_config: CopilotConfig
    ) -> "CopilotRuntimeConfig":
        recursion_limit = _get_int_param(
            copilot_config,
            default=1000,
            keys=("deepagent_recursion_limit", "deepAgentRecursionLimit"),
        )
        repeated_tool_batch_limit = _get_int_param(
            copilot_config,
            default=3,
            keys=(
                "deepagent_repeated_tool_batch_limit",
                "deepAgentRepeatedToolBatchLimit",
            ),
        )
        repeated_todo_limit = _get_int_param(
            copilot_config,
            default=2,
            keys=(
                "deepagent_repeated_todo_limit",
                "deepAgentRepeatedTodoLimit",
            ),
        )
        delegated_task_retry_limit = _get_int_param(
            copilot_config,
            default=1,
            keys=(
                "deepagent_delegated_task_retry_limit",
                "deepAgentDelegatedTaskRetryLimit",
            ),
        )
        session_notes_max_chars = _get_int_param(
            copilot_config,
            default=6000,
            keys=("copilot_session_notes_max_chars",),
        )
        loop_guard_pivot_escalation_after = _get_int_param(
            copilot_config,
            default=2,
            keys=(
                "deepagent_loop_guard_pivot_escalation_after",
                "deepAgentLoopGuardPivotEscalationAfter",
            ),
        )
        return cls(
            recursion_limit=max(MIN_RECURSION_LIMIT, recursion_limit),
            repeated_tool_batch_limit=max(
                MIN_REPEATED_TOOL_BATCH_LIMIT, repeated_tool_batch_limit
            ),
            repeated_todo_limit=max(
                MIN_REPEATED_TODO_LIMIT, repeated_todo_limit
            ),
            delegated_task_retry_limit=max(
                MIN_DELEGATED_TASK_RETRY_LIMIT, delegated_task_retry_limit
            ),
            session_notes_max_chars=max(
                MIN_SESSION_NOTES_CHARS, session_notes_max_chars
            ),
            loop_guard_pivot_escalation_after=max(
                MIN_LOOP_GUARD_PIVOT_ESCALATION_AFTER,
                loop_guard_pivot_escalation_after,
            ),
        )


def create_chat_model(
    copilot_config: CopilotConfig,
    *,
    plugin_api_key: str,
):
    additional_params = copy.deepcopy(copilot_config.additional_params)

    if "api_key" not in additional_params:
        additional_params["api_key"] = plugin_api_key

    computed_additional_params: dict[str, ty.Any] = {}
    if copilot_config.model_provider == "openai":
        import httpx

        if not additional_params.pop("trust_env", True):
            computed_additional_params["http_client"] = httpx.Client(
                trust_env=False
            )
            computed_additional_params["http_async_client"] = httpx.AsyncClient(
                trust_env=False
            )
    if copilot_config.model_provider == "google_anthropic_vertex":
        credentials_data = additional_params.pop("credentials")
        from google.oauth2 import service_account

        credentials = service_account.Credentials.from_service_account_info(
            credentials_data,
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
        )
        computed_additional_params["credentials"] = credentials
    if "max_retries" not in additional_params:
        additional_params["max_retries"] = 4

    return init_chat_model(
        copilot_config.model_name,
        model_provider=copilot_config.model_provider,
        rate_limiter=InMemoryRateLimiter(requests_per_second=15 / 60),
        **additional_params,
        **computed_additional_params,
    )


def exception_to_user_message(exception: Exception) -> str:
    if is_rate_limit_error(exception):
        return "This request was rate-limited. Please try again soon."
    if is_quota_exceeded(exception):
        return "User's quota exhausted. Upgrade or contact us to continue."
    if is_context_length_error(exception):
        return (
            "This copilot conversation exceeded the model context window. "
            "Please clear the conversation and try again."
        )
    if is_transient_provider_error(exception):
        return (
            "The model provider connection dropped while streaming a response. "
            "Please try again."
        )
    if is_tool_execution_configuration_error(exception):
        return (
            "I hit an internal copilot tool-execution error while trying to "
            "use a tool. Please reload the plugin and try again."
        )
    return (
        "I encountered an error while processing your request. "
        "Please try again or rephrase your question."
    )


def is_quota_exceeded(exception: Exception) -> bool:
    return str(getattr(exception, "status_code", "")) == "402"


def is_rate_limit_error(exception: Exception) -> bool:
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

    exception_str = str(exception).lower()
    return "rate" in exception_str and "limit" in exception_str


def is_tool_execution_configuration_error(exception: Exception) -> bool:
    exception_str = str(exception).lower()
    return (
        "awrap_tool_call is not available" in exception_str
        or "tool-execution error" in exception_str
    )


def is_context_length_error(exception: Exception) -> bool:
    exception_str = str(exception).lower()
    return any(
        marker in exception_str
        for marker in (
            "prompt is too long",
            "context window",
            "maximum context",
            "context length",
            "too many tokens",
            "tokens >",
            "input too long",
            "contextwindowexceeded",
        )
    )


def is_transient_provider_error(exception: Exception) -> bool:
    if isinstance(
        exception,
        (
            httpx.RemoteProtocolError,
            httpx.ReadError,
            httpx.ReadTimeout,
            httpx.ConnectError,
            httpx.PoolTimeout,
        ),
    ):
        return True
    if isinstance(
        exception, ollama.ResponseError
    ) and exception.status_code in {502, 503, 504}:
        return True

    status_code = str(getattr(exception, "status_code", "")).strip()
    if status_code in {"502", "503", "504"}:
        return True

    exception_str = str(exception).lower()
    return any(
        marker in exception_str
        for marker in (
            "503 service temporarily unavailable",
            "502 bad gateway",
            "504 gateway timeout",
            "remoteprotocolerror",
            "peer closed connection",
            "incomplete chunked read",
            "server disconnected",
            "connection reset",
            "temporarily unavailable",
        )
    )


def _get_string_param(
    copilot_config: CopilotConfig, *, keys: tuple[str, ...]
) -> ty.Optional[str]:
    for key in keys:
        value = copilot_config.additional_params.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _get_int_param(
    copilot_config: CopilotConfig,
    *,
    default: int,
    keys: tuple[str, ...],
) -> int:
    text = _get_string_param(copilot_config, keys=keys)
    if text is None:
        return default
    try:
        return int(text)
    except ValueError:
        return default
