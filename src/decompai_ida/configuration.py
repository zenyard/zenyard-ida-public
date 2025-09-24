import typing as ty
from inspect import cleandoc
from pathlib import Path

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

    require_confirmation_per_db: bool = True

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

    ask_for_binary_instructions: bool = True

    show_initial_upload_message: bool = True

    def with_user_config(
        self,
        *,
        api_url: Url,
        api_key: str,
        require_confirmation_per_db: bool,
    ) -> "PluginConfiguration":
        return PluginConfiguration(
            api_url=api_url,
            api_key=api_key,
            require_confirmation_per_db=require_confirmation_per_db,
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
        <Ask before running Zenyard on files opened for the first time.:C>>
        %A
    """)
    REQUIRE_CONFIRMATION_FLAG = 1 << 0

    current_config = read_configuration_sync()

    api_key_arg = ida_kernwin.Form.StringArgument(  # type: ignore
        40,
        current_config.api_key,
    )
    api_url_arg = ida_kernwin.Form.StringArgument(  # type: ignore
        512,
        str(current_config.api_url),
    )
    checkboxes = ida_kernwin.Form.NumericArgument(  # type: ignore
        ida_kernwin.Form.FT_UINT64,
        (
            REQUIRE_CONFIRMATION_FLAG
            if current_config.require_confirmation_per_db
            else 0
        ),
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
            checkboxes.arg,
            errors_arg.arg,
        )

        if result != ida_kernwin.ASKBTN_YES:
            return False

        try:
            new_config = current_config.with_user_config(
                api_key=api_key_arg.value.strip(),
                api_url=api_url_arg.value.strip(),
                require_confirmation_per_db=(
                    checkboxes.value & REQUIRE_CONFIRMATION_FLAG
                ),
            )
            break
        except ValidationError as error:
            errors_arg.value = _format_validation_error(error)

    _write_configuration(new_config)
    return True


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
