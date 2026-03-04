from dataclasses import dataclass
import json
import re
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

API_URL = globals().get("ZENYARD_API_URL", "https://api.zenyard.ai")
REPOSITORY = globals().get("ZENYARD_REPOSITORY", "zenyard/zenyard-ida-public")
INSTALL_LOCATION = f"git+https://github.com/{REPOSITORY}.git"
STUB_FILE_URL = (
    f"https://raw.githubusercontent.com/{REPOSITORY}/main/decompai_stub.py"
)

user_dir = Path(ida_diskio.get_user_idadir())
stub_path = user_dir / "plugins" / "decompai_stub.py"
packages_path = user_dir / "plugins" / "decompai_packages"
config_path = user_dir / "decompai.json"
accepted_eula_version_key = "accepted_eula_version"


def is_current_eula_accepted() -> bool:
    if not config_path.exists():
        return False

    with config_path.open("r") as f:
        config = json.load(f)

    return config.get(accepted_eula_version_key) == EULA_VERSION


def mark_current_version_accepted():
    with config_path.open("r") as f:
        config = json.load(f)

    config[accepted_eula_version_key] = EULA_VERSION

    with config_path.open("w") as f:
        json.dump(config, f)


def main():
    try:
        config_exists = config_path.exists()

        check_prerequisites()

        if not is_current_eula_accepted():
            if not run_in_ui(confirm_eula):
                print("[+] Terms of Use not accepted, stopping")
                return

        if not config_exists:
            api_key = request_api_key()
        else:
            print("[+] Will use existing API key")
            api_key = None

        print("[+] Installing or upgrading package (may take a minute)")
        install_or_upgrade_package(INSTALL_LOCATION, target=packages_path)

        print("[+] Installing plugin stub file")
        install_stub_file()

        if not config_exists:
            print("[+] Installing API key")
            assert api_key is not None
            install_configuration(api_key=api_key)

        mark_current_version_accepted()

        print("[+] All set!")
        stop_running_plugin()
        run_in_ui(
            lambda: ida_kernwin.info(
                "Zenyard was installed successfully, restart IDA to use it."
            )
        )

    except Exception as ex:
        message = f"Install failed: {ex}"
        run_in_ui(lambda: ida_kernwin.warning(message))


_IDA_VERSION_PATTERN = re.compile(r"^(\d+)\.(\d+)")


@dataclass(frozen=True, order=True)
class IdaVersion:
    major: int
    minor: int
    sp: int

    def __str__(self) -> str:
        if self.sp == 0:
            return f"{self.major}.{self.minor}"
        else:
            return f"{self.major}.{self.minor}sp{self.sp}"


def get_ida_version() -> IdaVersion:
    ida_version = run_in_ui(ida_kernwin.get_kernel_version)
    m = _IDA_VERSION_PATTERN.match(ida_version)
    if m is None:
        raise Exception("Can't parse IDA version")
    major = int(m.group(1))
    minor = int(m.group(2))
    service_pack = (
        1
        if (major, minor) == (9, 0) and hasattr(ida_kernwin, "BWN_DISASMS")
        else 0
    )
    return IdaVersion(major=major, minor=minor, sp=service_pack)


def check_prerequisites():
    py_major, py_minor = sys.version_info.major, sys.version_info.minor
    if (py_major, py_minor) < (3, 11):
        raise Exception(f"Python 3.11 or higher required, got {sys.version}")

    ida_version = get_ida_version()
    if ida_version < IdaVersion(9, 0, sp=1):
        raise Exception("IDA 9.0sp1 or higher required")

    if shutil.which("git") is None:
        raise Exception("Git is required for installation")

    try:
        import pip  # type: ignore  # noqa: F401
    except ImportError:
        raise Exception("Pip is required for installation")

    try:

        def import_qt():
            if ida_version >= IdaVersion(9, 2, 0):
                from PySide6 import QtWidgets as QtWidgets  # type: ignore
                from PySide6 import QtCore as QtCore  # type: ignore
                from PySide6 import QtGui as QtGui  # type: ignore
            else:
                from PyQt5.QtCore import Qt as Qt  # type: ignore
                from PyQt5.QtGui import QPixmap as QPixmap  # type: ignore
                from PyQt5.QtWidgets import QApplication as QApplication  # type: ignore

        run_in_ui(import_qt)

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


def install_stub_file():
    stub_path.parent.mkdir(parents=True, exist_ok=True)

    req = Request(STUB_FILE_URL)
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


def confirm_eula() -> bool:
    """
    Modal EULA dialog. Prefers PySide6, falls back to PyQt5.
    Returns True if user clicks Accept, else False.
    """
    try:
        from PySide6 import QtGui, QtWidgets  # type: ignore

        dialog_exec = QtWidgets.QDialog.exec
    except Exception:
        from PyQt5 import QtGui, QtWidgets  # type: ignore

        dialog_exec = QtWidgets.QDialog.exec_

    _ = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])

    dlg = QtWidgets.QDialog()
    dlg.setWindowTitle("Accept Zenyard Terms of Use")
    dlg.setModal(True)

    layout = QtWidgets.QVBoxLayout(dlg)

    intro = QtWidgets.QLabel(
        "Please review and accept the following Terms of Use:"
    )
    intro.setWordWrap(True)
    layout.addWidget(intro)

    text = QtWidgets.QPlainTextEdit()
    text.setReadOnly(True)
    text.setPlainText(EULA)
    text.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
    text.setWordWrapMode(QtGui.QTextOption.WrapAtWordBoundaryOrAnywhere)
    fixed = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont)
    fixed.setPointSize(max(fixed.pointSize(), 12))
    text.setFont(fixed)
    layout.addWidget(text, 1)

    btn_row = QtWidgets.QHBoxLayout()
    btn_row.addStretch(1)

    btn_cancel = QtWidgets.QPushButton("Cancel")
    btn_accept = QtWidgets.QPushButton("Accept")
    btn_accept.setDefault(True)

    btn_cancel.clicked.connect(dlg.reject)
    btn_accept.clicked.connect(dlg.accept)

    btn_row.addWidget(btn_cancel)
    btn_row.addWidget(btn_accept)
    btn_row.addStretch(1)
    layout.addLayout(btn_row)

    dlg.resize(800, 600)

    return dialog_exec(dlg) == QtWidgets.QDialog.Accepted


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


EULA_VERSION = 1  # Increment when changing EULA
EULA = r"""
Terms of Use

Last Updated: February 1, 2026

Please review the terms and conditions that govern your use of the Zenyard platform (the “Solution”).
By using the Solution (as defined below), you acknowledge and agree to these Terms of Use. We are pleased to provide you with access to the Solution under these terms. If you do not agree to these Terms of Use, please refrain from using the Solution.

1. PREAMBLE
1.1 Zenyard Ltd. (“Company”, “we”, “our”, “us”) welcomes you to our Solution, as defined below, and the services provided by the Company (collectively, the “Services”). 
1.2 PLEASE READ CAREFULLY THESE TERMS OF USE (“TERMS OF USE”). BY USING THE SERVICES, YOU CONFIRM THAT YOU HAVE READ, UNDERSTOOD AND AGREE TO BE BOUND BY THESE TERMS OF USE IN THEIR ENTIRETY.
IF YOU DO NOT AGREE TO BE BOUND BY THESE TERMS OF USE, THEN DO NOT USE THE SERVICES.
1.3 By Using the Services, you hereby warrant and represent that you are aware that you are not obligated by law to Use the Services and to provide any data, and any provision of it is based on your free will.
1.4 If you are using the Services on behalf of a company (such as your employer), or other legal entity, you represent and warrant that you have the authority to bind that entity to these Terms of Use. In that case, “User”, “you” and “your” will refer to that entity. 
1.5 Furthermore, by accepting these Terms of Use, you hereby waive any rights or requirements under any applicable laws or regulations in any jurisdiction, which require an original (non-electronic) signature or delivery or retention of non-electronic records, to the maximum extent permitted under applicable law.
​
2. DEFINITIONS. 
In these Terms of Use, the following terms shall have the meaning set forth below:
2.1 “Solution” refers to a computer code analysis platform powered by artificial intelligence designed to streamline complex analysis tasks of decompiled code. It can integrate with industry-standard decompilation platforms to enhance code readability and comprehension by analyzing its structure, functionality and other parameters. It can also perform various analyses to determine the code's purpose and present findings interactively to the User.
2.2 “Results” refers to any and all outcomes, findings, analyses, reports, or outputs generated by the Solution as a result of its operation, including but not limited to enhanced code readability, structural analysis, functionality descriptions, and interactive presentations provided to the User.
2.3 “Third Party Software” means any software or tools provided by third parties that may interact or interface with the Solution (including, but not limited, in the Solution), which shall be subject to the licenses and provisions of such third party proprietors. 
2.4 “Use” or “Usage” or “Using” refers to any form of accessing, interacting with, or operating the Solution, including but not limited to utilizing its features or interfacing with it.
2.5 “User”, “you” or “your” means a legal or natural person who has subscribed to the Services and is authorized by us to access and use the Services.
2.6 "User Data" means any information, as well as computer code and components of computer code, provided or submitted by a User to the Solution, used with the Solution, required to subscribe to the Solution, or otherwise sent or communicated to the Company in connection with the use of the Solution. This includes, but is not limited to, data relating to the User or any third party. 
2.7 "Payment Terms" means the terms and conditions governing payment obligations for the use of the Services, as determined by the applicable agreement, purchase order, proposal, or other transaction-specific arrangement between the purchasing legal entity and the Company, including but not limited to fees, payment schedules, payment methods, and the license period.

3. USE OF THE SOLUTION
3.1 Access to the Services
3.1.1 Based on your pre-selected deployment procedure, the following terms apply:
(i) Server Component: 
●	“On-Premises Deployment”: Refers to a setup where the Solution's server component is installed and operated on hardware you procure, deploy, install and maintain, or hardware that is procured for you by us, or on a virtual private server (VPS) or equivalent cloud infrastructure (such as AWS, Azure, or GCP) that is under your control. This deployment option requires you to provide a server meeting the specifications provided by the Company and deploy the server in your local or private network according to detailed installation guidelines that will be provided. For On-Premises Deployments, you are solely responsible for procurement, hosting, fees, security, backups, monitoring, patching, maintenance, and capacity of this infrastructure and environment (including the server component and any supporting systems). In such cases, the Company has no responsibility or liability for any of the foregoing. The Company will not have access to this system unless you grant permission for specific support purposes.
●	“Cloud-Based Deployment”: Refers to a configuration where the Solution's server component is hosted and maintained by the Company. The Company will provide secure access to the server component, ensuring regular updates and maintenance without requiring direct involvement from you.
(ii) Client Component: The client component, whether provided as a plugin for existing Third-Party Software or as standalone software from us, must be installed and/or configured on each user’s computer. Each client installation must be configured to connect to the selected server component (either On-Premises or Cloud-Based Deployment).
3.1.2 For Cloud-Based Deployments, the installed certificate and/or credentials enabling the connection to the cloud is non-transferable and limited strictly to use within your organization. Sharing credentials, including certificates, with any other users or organizations outside of the purchasing entity is strictly prohibited.
3.1.3 Subject to your compliance with the Terms of Use and due payment for the Services as per the Payment Terms, the Company hereby grants to you a personal, nonexclusive, revocable, non-assignable, non-transferable, non-sublicensable temporary, limited right to (a) use the Services for your own personal or internal business purposes only, unless otherwise authorized by us; and (b) use the documentation provided within the Services. Pursuant to the aforementioned, if you are a representative of a legal entity, you may access the Services provided that you are authorized to use the Solution on behalf of such legal entity in accordance with these Terms of Use. The use of the Solution must align with the number of licenses purchased. Any usage exceeding the licensed number of users is strictly prohibited.
3.1.4 Prior to downloading, installing or any Use of the Solution, it may be necessary to acquire and install Third Party Software from various software licensors as determined by the Company. The User shall be solely responsible for providing, maintaining and ensuring the compatibility of all hardware, software, electrical and other physical requirements necessary for User’s access to and use of the Services, including, without limitation, third party licensed software, telecommunications and internet access connections and links, web browsers or other equipment, and programs and services required to access and use the Services. Third Party Software shall be subject to its Terms of Service or licenses provisions of their respective proprietors. With no derogation from any other liability limitations and exclusions as provided in these Terms of Use, including as detailed in article ‎8 hereinafter, THE COMPANY BEARS NO RESPONSIBILITY OR LIABILITY WHATSOEVER FOR THE THIRD PARTY SOFTWARE. In addition and under no circumstance shall the Company be responsible or liable whatsoever, directly or indirectly, for the Third Party Software, including but not limited to its apparatus, quality or effectivity, modifications or alterations or changes/ updates/ upgrades or its installation or for providing any type of maintenance or support in relation to such Third Party Software.

3.2 Conditions To Use the Services
3.2.1 Use of the Solution and/or Services is conditional upon full and timely payment of all applicable fees as outlined in the agreed-upon Payment Terms. This includes fees for licenses of the Solution and, in the case of Cloud-Based Deployments, any associated cloud usage fees. The Company reserves the right to suspend or terminate access if payment is not received according to the agreed-upon terms.
3.2.2 To Use the Services, you must be: (a) Possess the legal right and ability to enter into a legally binding agreement with us; and (b) Agree and warrant to Use the Services in accordance with these Terms of Use.

3.3 Your Responsibility and Restrictions
3.3.1 You are responsible for any activity that occurs through the Use of the Services and you agree that you will not Use the Services for anyone other than for yourself.
3.3.2 You hereby undertake that the use of the Services and the Results shall be made only in accordance with applicable laws, regulations and other instructions and guidelines which are related to your Use and shall not use it for any purpose other than that which is intended pursuant to the terms of these Terms of Use.
3.3.3 You will Use the Services according to these Terms of Use and not abuse the Services.
3.3.4 Without limiting the foregoing, you will not do, or authorize, or permit any third party to do any of the following during the license period or after it has ended (as defined in the Payment Terms): 
1.	rent, lease, loan, license, sell, redistribute or sublicense the Services, distribute or copy the Services, crawl, reverse engineer, decompile, disassemble, or attempt to discover the source code for the Services or any methods, algorithms or procedures from the Services, modify, adapt, translate, alter, or create any derivative works of the Services;
2.	remove, alter or obscure any copyright, trademark or other proprietary rights notice on or in the Services;
3.	Use the Services for any illegal purpose, or in violation of any license or applicable law including export laws, including, without limitation, laws governing intellectual property and other proprietary rights, data protection and privacy, etc.;
4.	Alter, circumvent, or transfer any product, key, or license restrictions, or reassign any named user license or entitlement;
5.	attempt to gain unauthorized access to the Services or any part of it, computer systems or networks connected to the Services through hacking or any other means or interfere or attempt to interfere with the proper working of the Services or any activities conducted through the Services by any means, including uploading or otherwise disseminating viruses, worms, or other malicious code;
6.	exploit the Services in any unauthorized way whatsoever, including but not limited to, by trespassing or burdening network capacity;
7.	continue to access or use the Solution or Services after the license period, as defined in the Payment Terms, has ended;
8.	attempt to use or allow the use of more licenses, users, or installations of the Solution than you have purchased or are authorized to use as defined in the Payment Terms, or bypass, override, or manipulate the licensing system in any way, including unauthorized sharing of license keys or using shared logins;
9.	engage in any conduct that poses a security risk to the Services, such as attempting to bypass security measures or introduce vulnerabilities. 
3.3.5 For On-Premises Deployments, you are solely responsible for procurement, hosting, fees, security, backups, monitoring, patching, maintenance, and capacity of the infrastructure and environment used to operate the Solution (including the server component and any supporting systems). The Company has no responsibility or liability for any of the foregoing.
​
3.4 User Data
3.4.1 For On-Premises Deployments, the Company assures you that it will not have access to any User Data processed within the on-premises Solution, unless you voluntarily provide such data or grant the Company access.
3.4.2 You are responsible for ensuring that any User Data you submit to the Solution during your use of the Solution is lawfully obtained by you and is correct, accurate, current and complete. 
3.4.3 You are solely responsible for your User Data. You assume all risks associated with the use of your User Data, including any reliance on its accuracy, completeness, or usefulness by others, or any disclosure of your User Data that personally identifies you or any third party. You may not represent or imply to others that your User Data is in any way provided, sponsored, or endorsed by the Company. Because you alone are responsible for your User Data, you may expose yourself to liability if, for example, your User Data violates the Terms of Use or applicable law. We are not obligated to backup any User Data, and your User Data may be deleted at any time without prior notice. You are solely responsible for creating and maintaining your own backup copies of your User Data if you desire. 
3.4.4 For Cloud-Based Deployments of the Solution, we reserve the right (but have no obligation) to review any User Data submitted to the Solution and to investigate or take appropriate action against you in our sole discretion if you violate the Terms of Use or otherwise create liability for the Company or any other person. Such action may include removing or modifying your User Data, suspending or terminating your access to the Services, or reporting you to law enforcement authorities.
3.4.5 You retain ownership of any User Data you provide when using the Services. When using the Cloud-Based Deployment of the Solution, you grant the Company a worldwide, royalty-free, sub-licensable, and transferable license to use, reproduce, study, research, analyze, process, modify, create derivative works of, and otherwise use your User Data. This license enables the Company to incorporate your User Data into the Solution, share it with third-party service providers, and use it for purposes such as improving the Solution, conducting user analyses, and developing new features. You waive any moral rights or attribution claims related to your User Data. Additionally, you agree that the Company may review and use any feedback, data, or other information you provide through the use of the Solution, including data uploaded or created through the Solution or information related to your use or performance of the Solution. The Company may use this information to verify adherence to these Terms of Use, improve the Solution, and for other development, diagnostic, and corrective purposes. The Company may also disclose aggregated, anonymized data derived from your usage. 

3.5 Privacy Policy
3.5.1 For the avoidance of doubt, the Solution is not intended for the processing of any Personal Data and you hereby represent that you will not include any Personal Data within the User Data uploaded to the Solution. If Personal Data is nonetheless included within the User Data, you warrant that you are legally permitted to do so, including granting the Company the license detailed in Section 3.4.5 above in relation to such Personal Data.
3.5.2 The Company’s collection and use of personal data in connection with the Services is described in the Company’s Privacy Policy, which forms an integral part of these Terms of Use and is available on the Company’s website. 
3.5.3 The Privacy Policy governs how personal data is handled and processed and shall prevail in the event of any inconsistency with these Terms of Use.
3.5.4 Except as expressly stated in the Privacy Policy, these Terms of Use do not regulate the processing of personal data. 
3.5.5 The Privacy Policy is available and may be reviewed at the following link: https://www.zenyard.ai/privacy. 

4. OWNERSHIP AND INTELLECTUAL PROPERTY RIGHTS
4.1 Except for User Data that you provide, you acknowledge and agree that all the intellectual property rights, including copyrights, patents, trademarks, design rights related to the Services and trade secrets in the Services and their content are owned by the Company or our suppliers. All trademarks and all other marks, trade names, service marks, wordmarks, illustrations, images, or logos appearing in connection with the Services are, and remain, the exclusive property of the Company or its suppliers and are subject to the protection granted by applicable laws or international treaties related to intellectual property. Neither these Terms of Use, nor your access to the Services, transfers to you or any third party any rights, title or interest in or to such intellectual property rights, except for the limited access rights expressly set forth herein. There are no implied licenses granted under the Terms of Use.
4.2 The Solution contains information owned by (or licensed to) the Company, including name, logo, text, images, audio/visual works, icons and scripts and other materials provided on or through the Services. Except as provided herein or with our express prior written permission, none of the information provided by the Services may be copied, displayed, distributed, downloaded, licensed, modified, published, re-posted, reproduced, reused, sold, transmitted, used to create a derivative work or otherwise used for public or commercial purposes. Trademarks mentioned in the Services are the property of the Company or their respective owners. Nothing in the Services should be construed as granting, by implication, estoppel, or otherwise, any license or right to use any trademark without our prior written permission in each instance. 
4.3 In the event that you provide to the Company any suggestions, comments and feedback regarding the Services, you hereby grant the Company and its licensors a perpetual, irrevocable, worldwide, royalty-free license to freely use, have used, sell, modify, reproduce, transmit, license, sublicense (through multiple tiers of sublicensees), distribute (through multiple tiers of distributors), and otherwise commercialize such feedback in connection with the Services or related technologies.

5. DISCLAIMERS; THIRD PARTY SERVICES
5.1 The Services we provide you are based on the assumption that the information provided by you to the Company, including User Data, is complete, reliable true, comply with applicable law and correct. We do not supervise or otherwise check the information source, its validity, correctness, reliability, accuracy, lawfulness, completeness or any other aspect associated with it. By using the Services, you may encounter content or information that might be inaccurate, incomplete, delayed, misleading, illegal, offensive or otherwise harmful. You agree that the Company is not responsible for others’ content or information. We cannot always prevent this misuse of our Services, and you agree that we are not responsible for any such misuse.
5.2 Third parties have their own terms of use and privacy policies, and you should read these carefully before you submit any Personal Data to these third parties. We do not endorse or otherwise accept any responsibility or liability for the content of User Data provided to such third-party software, tools, websites or apps. While we use reasonable efforts to ensure that the Services are free from viruses and other malicious content, neither we, nor any other party involved in producing, hosting or delivering the Services assumes any responsibility, nor shall be liable for any damage to, or viruses that may infect your device. Except where required by applicable law, the Company shall not be liable to any User or other person for any loss or damage they may suffer as a result of viruses, or other malicious or harmful content that they access from, or through the Services.
5.3 Our Solution utilizes and leverages third-party AI tools made available as part of the Solution. By using the Services, you authorize us to use User Data as required to provide the Services through AI-powered systems, functionalities and any other . You acknowledge and agree to the Results generated through AI,  which means artificial intelligence technologies and algorithms capable of generating data, content, or outputs that resemble and simulate human-created content (including audio, code, images, text, and simulations) to provide the Solution and Services and improve our Solution.
5.4 By using our Services, you acknowledge and agree to the following:
1.	Results may not always be accurate, and you should not rely on them as your sole source of information or as a replacement for professional advice. The Company is not liable for any consequences arising from the use or reliance on the Results.
2.	You are responsible for evaluating the Results for accuracy, correctness and appropriateness for your use case, including conducting human review, before using or sharing the Results.
3.	The Services may produce Results that are incomplete, false, misleading or offensive, and such Results do not represent the views of the Company. 
4.	The Solution may use artificial intelligence models that may evolve over time. As such, the quality and nature of the Results may change as the Solution is updated.
​
6. NO WARRANTY. 
6.1 To the fullest extent permitted by applicable law, the Services are provided “as is” and on an “as available” basis with all faults, defects and errors, and without any warranty or representation of any kind. The Company specifically disclaims all warranties, whether expressed or implied, arising by law or otherwise, regarding the Services and their performance, suitability for your intended Use, including without limitation any implied warranty of title, merchantability, fitness for a particular purpose, non-infringement, that the Use of the Services will be uninterrupted or error free, or that all vulnerabilities and defects will be detected or corrected. 
6.2 THE SERVICES MAY BECOME INACCESSIBLE OR THEY MAY NOT FUNCTION PROPERLY WITH USERS’ WEB BROWSER, MOBILE DEVICE, OR OPERATING SYSTEM. THE COMPANY CANNOT BE HELD LIABLE FOR ANY PERCEIVED OR ACTUAL DAMAGES ARISING FROM THE SERVICES CONTENT, OPERATION, OR THE USE OR INABILITY TO USE OF THE SERVICES.
6.3 If you encounter any problem in the use of the Services, please contact us and we will employ reasonable efforts to support you.
6.4 We may update our Services from time to time, however, they may not always be complete or up-to-date. For Cloud-Based Deployments, updates may be applied automatically as part of our service maintenance. For On-Premises Deployments, updates are not automatic and must be initiated by You. While we strive for maximum availability of the Services, there may be interruptions, including, without limitation, due to scheduled maintenance, updates, emergency repairs, or failures in telecommunications links, software or equipment. 
6.5 We may remove any content from the Services at our discretion and without prior notice. Content, including User Data, that is removed from the Services may either be deleted or retained by the Company, based on its sole discretion, including (but not limited) to comply with legal obligations, but may not be retrievable without a valid court order or similar legal process. 

7. LIMITATION OF LIABILITY. To the maximum extent permitted by applicable law, in no event will the Company (including its service providers) be liable for any indirect, consequential, incidental, special, exemplary, or punitive damages, or liabilities whatsoever arising from, or relating to the Services (including, without limitation, due to your Use or inability to Use the Services) or these Terms of Use, whether based on contract, tort (including negligence), strict liability, or other theory, even if the Company has been advised of the possibility of such damages. If you are dissatisfied with the Services or any content thereon, your sole and exclusive remedy is to discontinue Using the Services. Without derogating from any of the foregoing, the total aggregate liability of the Company together with anyone on our behalf under these Terms of Use, if any (including our service providers), in connection with the Services will not exceed one-third of the amount paid to the Company for the Solution during the twelve (12) month period preceding the date on which the applicable liability claim arose.

8. RELEASE AND INDEMNIFICATION. You release, and agree to indemnify, defend and hold the Company, its officers, directors, employees, shareholders, and agents against any third party claims, suits, actions or harmless resulting from all liabilities, loss and damages (of every kind, whether known or unknown and suspected or unsuspected), including reasonable attorney’s fees, arising from or related to: (a) use or misuse of the Services, whether or not in violation of these Terms or applicable law; or (b) violation of this Terms. 

9. LIMITATION OF USE. 
9.1 The Company reserves the right to immediately restrict, suspend or block your Use of the Services, or change the Services, or a part of them, if in the Company’s sole opinion (A) you breach these Terms of Use or any applicable law; (B) you are misusing the Services; (C) to protect other users; (D) if you create risk or legal exposure for the Company; and (E) if you infringe intellectual property rights. 
9.2 The Company reserves the right at all times to disclose any information as the Company deems necessary to satisfy any applicable law, regulation, legal process or governmental request, in whole or in part, in the Company's sole discretion.
9.3 If you believe that your access to the Services has been suspended or terminated in error, you can contact us and we will employ reasonable efforts to respond. 
9.4 If you request the deletion of a content, information or account, and the Company concludes that such request shall be accepted, the Company will use commercially reasonable efforts to remove such content or information or suspend or terminate the account, at its sole discretion. 
9.5 The Company reserves the right not to delete and to retain any content, information or account if it is necessary for or due to: (A) technical limitations of our systems; or (B) where deletion would restrict our ability to: (a) investigate or identify illegal activity or violations of these Terms of Use or any applicable law; (b) protect the safety and security of our products, systems and users; (c) comply with a legal obligation, such as the preservation of evidence; or (d) comply with a request of a judicial or administrative authority, law enforcement or a government agency.

10. TERMINATION. The Company may immediately terminate your right to access and use the Solution if the Company believes or has reasonable grounds to suspect that you are violating or have violated the terms laid down in these Terms of Use. Upon termination of these Terms of Use, you agree that: (a) The right granted to you to Use the Services under these Terms of Use will terminate immediately; and (b) You must immediately upon receiving any notice of termination cease all Use of the Services and destroy or erase all copies of the Services in your possession or control.

11. AGE RESTRICTIONS. The Services are intended for a User who is not a minor. If you are minor according to your legal jurisdiction, you may not Use the Services, contact the Company or send the Company any User Data. By Using the Services, you hereby warrant and represent that you are not a minor. 

12. EXPORT LAWS AND SANCTIONS. U.S. GOVERNMENT EMBARGO. By Using the Services, you hereby warrant and represent that you are not located in a country that is subject to U.S. Government embargo, or otherwise designated by the U.S. Government as “terrorist supporting” country, and that you are not listed on any U.S. Government list of prohibited or restricted parties. 

13. ASSIGNMENT. You may not assign these Terms of Use, or any of your rights under these Terms of Use without the prior written consent of the Company, and any attempted assignment without such consent shall be void. The Company is free to assign its rights and obligations under these Terms of Use, without prior notification to you.

14. GOVERNING LAW AND JURISDICTION. Unless restricted by applicable law, these Terms of Use shall be governed by the laws of Israel (excluding its conflict of laws provisions) and any matter, or dispute arising in connection with them or in connection with the Services shall be subject to the exclusive jurisdiction of the competent courts of Tel Aviv, Israel. We make no representation that the Services are appropriate or available for use in all jurisdictions. Access to any part of the Services from jurisdictions where such access is illegal is strictly prohibited. If you choose to access the Services from such jurisdictions, you do so at your own risk. You are always responsible for your compliance with applicable laws.

15. FORCE MAJEURE. We will not be liable for any failure or delay in the performance of our obligations with regard to the Solution if such delay or failure is due to causes beyond our control including but not limited to acts of God, war, strikes or labor disputes, embargoes, government orders, pandemics, telecommunications, network, computer, server or Internet downtime, cyber-attacks, unauthorized access to the Company’s information technology systems by third parties or any other cause beyond the reasonable control of the Company.

16. SEVERABILITY. If any term of these Terms of Use is found to be unenforceable, or contrary to law, it will be modified to the least extent necessary to make it enforceable, and the remaining portions of these Terms of Use will remain in full force and effect.

17. NO WAIVER. No waiver of any right under the Terms of Use will be deemed effective unless contained in writing signed by the Company, and no waiver of any past or present right arising from any breach, or failure to perform will be deemed to be a waiver of any future rights arising out of these Terms of Use.

18. ENTIRE AGREEMENT. These Terms of Use are concluded between you and the Company. These Terms of Use, constitute the entire agreement between you and the Company with respect to the Use of the Services, and supersede all prior agreements, proposals, negotiations, representations or communications relating to the subject matter. However, these Terms of Use do not derogate from any other agreement between you and the Company. 

19. UPDATES and AMENDMENTS. We may update or amend these Terms of Use from time to time. Any changes will be posted on our website and will become effective as of the date indicated at the top of the updated Terms of Use, unless otherwise required by applicable law.  Where required by applicable law, or where changes materially affect your rights, we will use commercially reasonable efforts to provide prior notice of such changes. Your continued use of the Services after the effective date of the updated Terms of Use constitutes your acceptance of the amended Terms.

20. CONTACT US. Should you have any question or complaint regarding the Services, please contact us at contact@zenyard.ai
""".strip().replace("\t", "  ")


if __name__ == "__main__":
    threading.Thread(target=main).start()
