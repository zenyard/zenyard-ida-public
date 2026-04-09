import typing as ty
from dataclasses import dataclass
from inspect import cleandoc
from pathlib import Path
import uuid

import ida_diskio
import ida_kernwin
from pydantic import (
    BaseModel,
    StringConstraints,
    UrlConstraints,
    ValidationError,
)
from pydantic_core import Url

_CONFIG_FILENAME = "decompai.json"


class BadConfigurationFile(Exception):
    def __init__(self, config_path: Path):
        super().__init__(f"Missing or bad configuration file at {config_path}")


class PluginConfiguration(BaseModel, frozen=True):
    api_url: ty.Annotated[
        Url,
        UrlConstraints(
            allowed_schemes=["http", "https"],
            host_required=True,
            max_length=2048,
        ),
    ]

    api_key: ty.Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1, max_length=2048),
    ]

    log_level: ty.Optional[
        ty.Union[
            ty.Literal[
                "CRITICAL",
                "FATAL",
                "ERROR",
                "WARN",
                "WARNING",
                "INFO",
                "DEBUG",
            ],
            int,
        ]
    ] = None

    verify_ssl: bool = True

    request_binary_instructions: bool = True

    show_initial_upload_message: bool = True

    # Kept here so we don't override value from installer
    accepted_eula_version: ty.Optional[int] = None

    install_id: ty.Optional[str] = None

    disable_analytics: bool = False

    def with_user_config(
        self,
        *,
        api_url: Url,
        api_key: str,
    ) -> "PluginConfiguration":
        return PluginConfiguration(
            api_url=api_url,
            api_key=api_key,
            log_level=self.log_level,
            verify_ssl=self.verify_ssl,
        )


def read_configuration_sync() -> PluginConfiguration:
    config_path = get_config_path_sync()

    try:
        with config_path.open() as config_file:
            return PluginConfiguration.model_validate_json(config_file.read())

    except Exception:
        raise BadConfigurationFile(config_path)


def get_config_path_sync() -> Path:
    return Path(ida_diskio.get_user_idadir()) / _CONFIG_FILENAME


def show_configuration_dialog_sync() -> bool:
    FORM_DEFINITION = cleandoc("""
        Zenyard settings

        <API key   :A:40:64::>
        <Server URL:A:512:64::>
        %A
    """)

    current_config = read_configuration_sync()

    api_key_arg = ida_kernwin.Form.StringArgument(  # type: ignore
        40,
        current_config.api_key,
    )
    api_url_arg = ida_kernwin.Form.StringArgument(  # type: ignore
        512,
        str(current_config.api_url),
    )
    errors_arg = ida_kernwin.Form.StringArgument(  # type: ignore
        2048,
        "",
    )

    while True:
        result = ida_kernwin.ask_form(
            FORM_DEFINITION,
            api_key_arg.arg,
            api_url_arg.arg,
            errors_arg.arg,
        )

        if result != ida_kernwin.ASKBTN_YES:
            return False

        try:
            new_config = current_config.with_user_config(
                api_key=api_key_arg.value.strip(),
                api_url=api_url_arg.value.strip(),
            )
            break
        except ValidationError as error:
            errors_arg.value = _format_validation_error(error)

    _write_configuration(new_config)
    return True


@dataclass(frozen=True)
class SetupAnalyticsConfigResult:
    install_id: str
    analytics_disabled: bool
    is_first_install: bool


def setup_analytics_config_sync() -> SetupAnalyticsConfigResult:

    current = read_configuration_sync()
    updates: dict[str, ty.Any] = {}

    is_first_install = current.install_id is None
    if is_first_install:
        updates["install_id"] = str(uuid.uuid4())

    if updates:
        current = current.model_copy(update=updates)
        _write_configuration(current)

    assert current.install_id is not None
    return SetupAnalyticsConfigResult(
        install_id=current.install_id,
        analytics_disabled=current.disable_analytics,
        is_first_install=is_first_install,
    )


def update_configuration_sync(updates: dict[str, ty.Any]):
    current = read_configuration_sync()
    updated = current.model_copy(update=updates)
    _write_configuration(updated)


def _write_configuration(new_config: PluginConfiguration):
    config_path = get_config_path_sync()
    with config_path.open("w") as config_file:
        config_file.write(new_config.model_dump_json(indent=4))


def _format_validation_error(error: ValidationError) -> str:
    FIELD_NAMES: dict[tuple, str] = {
        ("api_key",): "API key",
        ("api_url",): "Server URL",
    }

    formatted_field_errors = list[str]()
    for field_error in error.errors():
        field_name = FIELD_NAMES.get(field_error["loc"]) or ".".join(
            str(part) for part in field_error["loc"]
        )
        message = field_error["msg"]
        formatted_field_errors.append(f"{field_name}: {message}")

    return "\n".join(formatted_field_errors)
