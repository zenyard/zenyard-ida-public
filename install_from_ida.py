# Quick installation from IDA, based on:
#   https://github.com/eset/ipyida/blob/master/install_from_ida.py

import base64
import json
import shutil
import subprocess
import sys
import threading
import typing as ty
from pathlib import Path
from textwrap import indent
from urllib.request import Request, urlopen
from uuid import UUID, uuid4

import ida_diskio
import ida_kernwin

API_URL = "https://api.zenyard.ai"
GIT_TOKEN = globals().get("GIT_TOKEN")
INSTALL_LOCATION = (
    f"git+https://{GIT_TOKEN}@github.com/zenyard/decompai-ida-public.git"
)
STUB_FILE_URL = "https://raw.githubusercontent.com/zenyard/decompai-ida-public/main/decompai_stub.py"

user_dir = Path(ida_diskio.get_user_idadir())
stub_path = user_dir / "plugins" / "decompai_stub.py"
packages_path = user_dir / "plugins" / "decompai_packages"
config_path = user_dir / "decompai.json"


def main():
    try:
        if not isinstance(GIT_TOKEN, str):
            raise Exception("Missing or invalid git token")

        config_exists = stub_path.exists()

        check_prerequisites()

        if not config_exists:
            api_key = request_api_key()
        else:
            print("[+] Will use existing API key")
            api_key = None

        print("[+] Installing or upgrading package (may take a minute)")
        install_or_upgrade_package(INSTALL_LOCATION, target=packages_path)

        print("[+] Installing plugin stub file")
        install_stub_file(GIT_TOKEN)

        if not config_exists:
            print("[+] Installing API key")
            assert api_key is not None
            install_configuration(api_key=api_key)

        print("[+] All set!")
        stop_running_plugin()
        run_in_ui(
            lambda: ida_kernwin.info(
                "DecompAI was installed successfully, restart IDA to use it."
            )
        )

    except Exception as ex:
        message = f"Install failed: {ex}"
        run_in_ui(lambda: ida_kernwin.warning(message))


def check_prerequisites():
    if sys.version_info < (3, 9):
        raise Exception(f"Python 3.9 or higher required, got {sys.version}")

    ida_version = run_in_ui(ida_kernwin.get_kernel_version)
    ida_major = int(ida_version.split(".")[0])
    if ida_major < 9:
        raise Exception("IDA 9.0 or higher required")

    if shutil.which("git") is None:
        raise Exception("Git is required for installation")

    try:
        import pip  # type: ignore  # noqa: F401
    except ImportError:
        raise Exception("Pip is required for installation")

    try:
        # IDA ships with PyQt5 version per Python release. Not being able to
        # import PyQt5 is a sign of IDA being incompatible with Python.
        from PyQt5.QtCore import Qt  # noqa: F401
        from PyQt5.QtGui import QPixmap  # noqa: F401
        from PyQt5.QtWidgets import QApplication  # noqa: F401
    except ImportError:
        py_version = f"{sys.version_info.major}.{sys.version_info.minor}"

        raise Exception(
            f"IDA {ida_version} isn't compatible with Python {py_version}. "
            "Please upgrade IDA or downgrade Python."
        )


def request_api_key():
    api_key = run_in_ui(
        lambda: ida_kernwin.ask_text(
            36, "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "Enter API key"
        )
    )

    if api_key is None:
        raise Exception("No API key entered")

    try:
        api_key = str(UUID(api_key.strip()))
    except ValueError:
        raise Exception("Invalid API key")

    return api_key


def get_hidden_window_startupinfo():
    if sys.platform == "win32":
        si_hidden_window = subprocess.STARTUPINFO()
        si_hidden_window.dwFlags = subprocess.STARTF_USESHOWWINDOW
        si_hidden_window.wShowWindow = subprocess.SW_HIDE
        return si_hidden_window
    else:
        return None


def install_or_upgrade_package(source: str, *, target: Path):
    temp_root = target.with_suffix(".temp")

    # Clear files from previous installation
    if temp_root.exists():
        shutil.rmtree(temp_root, ignore_errors=True)

    # We download to another destination, since pip may not be able to replace
    # shared libs currently loaded to IDA.
    work_dir = temp_root / str(uuid4())
    work_dir.mkdir(parents=True)
    download_path = work_dir / "download"

    try:
        run_pip(
            ("install", "--upgrade", "--target", str(download_path), source)
        )
    except subprocess.CalledProcessError as ex:
        all_output = indent(
            "\n".join((ex.stdout, ex.stderr)).strip(),
            prefix="[pip] ",
            predicate=lambda line: True,
        )
        print(all_output)
        raise

    if target.exists():
        target.rename(work_dir / "old")
    download_path.rename(target)

    shutil.rmtree(temp_root, ignore_errors=True)


def run_pip(args: ty.Iterable[str]):
    subprocess.run(
        [python_executable(), "-m", "pip", *args],
        startupinfo=get_hidden_window_startupinfo(),
        capture_output=True,
        check=True,
        text=True,
        encoding="utf-8",
    )


def python_executable() -> Path:
    base_path = Path(sys.prefix)
    py_version = sys.version_info
    candidates = [
        base_path / "Scripts" / "Python.exe",
        base_path / "Python.exe",
        base_path / "bin" / f"python{py_version.major}",
        base_path / "bin" / f"python{py_version.major}.{py_version.minor}",
        base_path / "Python",
    ]

    existing = next(
        (candidate for candidate in candidates if candidate.exists()), None
    )

    if existing is None:
        raise Exception("Can't find Python executable")

    return existing


def install_stub_file(git_token: str):
    stub_path.parent.mkdir(parents=True, exist_ok=True)

    req = Request(STUB_FILE_URL)
    req.add_header(
        "Authorization",
        f"Basic {base64.b64encode(git_token.encode('utf-8')).decode('utf-8')}",
    )
    with (
        urlopen(req) as remote_input,
        stub_path.open("wb") as local_output,
    ):
        shutil.copyfileobj(remote_input, local_output)


def install_configuration(*, api_key: str):
    config_path.parent.mkdir(parents=True, exist_ok=True)

    with config_path.open("w") as config_output:
        json.dump({"api_url": API_URL, "api_key": api_key}, config_output)


def stop_running_plugin():
    try:
        from decompai_ida import main

        main.stop()

    except Exception:
        # Ignore - maybe it's not running.
        pass


T = ty.TypeVar("T")


class NoOutput:
    pass


def run_in_ui(func: ty.Callable[[], T]) -> T:
    output: ty.Union[T, NoOutput] = NoOutput()
    error: ty.Optional[Exception] = None

    def perform():
        nonlocal output, error
        try:
            output = func()
        except Exception as ex:
            error = ex

    ida_kernwin.execute_sync(perform, ida_kernwin.MFF_FAST)

    if error is not None:
        raise error
    else:
        assert not isinstance(output, NoOutput)
        return output


if __name__ == "__main__":
    threading.Thread(target=main).start()
