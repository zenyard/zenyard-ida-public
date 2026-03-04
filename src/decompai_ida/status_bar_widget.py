import importlib.resources
from inspect import cleandoc

from qtpy import QtGui
from qtpy.QtCore import Qt, Signal
from qtpy.QtGui import QPixmap
from qtpy.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QWidget,
)

from decompai_ida import assets
from decompai_ida.ui.status_bar_view_model import StatusBarViewModel


class StatusBarWidget(QWidget):
    save_results_clicked = Signal()
    upload_clicked = Signal()
    usage_clicked = Signal()

    @staticmethod
    def _build_stylesheet() -> str:
        return cleandoc("""
            _ClickableLabel[usageStatus="critical"] {
                color: #ff4444; 
                font-size: 12px;
                font-weight: bold;
            }
            _ClickableLabel[usageStatus="warning"] {
                color: #ffaa00;
                font-weight: normal;
            }
        """)

    def __init__(self, view_model: StatusBarViewModel):
        super().__init__()
        self.setStyleSheet(self._build_stylesheet())

        self.setFixedWidth(530)

        # HBoxLayout
        self._hbox = QHBoxLayout()
        self.setLayout(self._hbox)
        self._hbox.setContentsMargins(4, 0, 4, 1)
        self._hbox.setSpacing(4)

        # Zenyard icon
        self._icon = QLabel()
        self._hbox.addWidget(self._icon)
        self._icon.setPixmap(_load_icon("zenyard_icon.png"))
        self._icon.setFixedSize(18, 18)
        self._icon.setScaledContents(True)

        # Upload icon
        self._upload_icon = _ClickableLabel()
        self._hbox.addWidget(self._upload_icon)
        self._upload_icon.setPixmap(_load_icon("upload_icon.png"))
        self._upload_icon.setFixedSize(18, 18)
        self._upload_icon.setScaledContents(True)
        self._upload_icon.setVisible(False)
        self._upload_icon.clicked.connect(self.upload_clicked)
        view_model.upload_available.connect(self._upload_icon.setVisible)

        # Save results icon
        self._save_results_icon = _ClickableLabel()
        self._hbox.addWidget(self._save_results_icon)
        self._save_results_icon.setPixmap(_load_icon("save_results_icon.png"))
        self._save_results_icon.setFixedSize(18, 18)
        self._save_results_icon.setScaledContents(True)
        self._save_results_icon.setVisible(False)
        self._save_results_icon.clicked.connect(self.save_results_clicked)
        view_model.results_available.connect(self._save_results_icon.setVisible)

        # Warning icon
        self._warning_icon = QLabel()
        self._hbox.addWidget(self._warning_icon)
        self._warning_icon.setPixmap(_load_icon("warning_icon.png"))
        self._warning_icon.setFixedSize(18, 18)
        self._warning_icon.setScaledContents(True)
        self._warning_icon.setToolTip("Can't reach server")
        self._warning_icon.setVisible(False)
        view_model.disconnected_icon_visible.connect(
            self._warning_icon.setVisible
        )

        # Swift code available icon
        self._swift_code_available_icon = QLabel()
        self._hbox.addWidget(self._swift_code_available_icon)
        self._swift_code_available_icon.setPixmap(_load_icon("swift.png"))
        self._swift_code_available_icon.setFixedSize(18, 18)
        self._swift_code_available_icon.setScaledContents(True)
        self._swift_code_available_icon.setToolTip("Swift code available")
        self._swift_code_available_icon.setVisible(False)
        view_model.swift_source_available_icon_visible.connect(
            self._swift_code_available_icon.setVisible
        )

        # Label
        self._label = _ClickableLabel()
        self._hbox.addWidget(self._label)
        self._label.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        self._label.clicked.connect(self._on_label_click)
        self._label.setText("Starting")
        view_model.status_line.connect(self._label.setText)
        view_model.results_tooltip.connect(self._label.setToolTip)

        # Progress bar
        self._progress_bar = QProgressBar()
        self._hbox.addWidget(self._progress_bar)
        self._progress_bar.setFixedSize(100, 18)
        self._progress_bar.setVisible(False)
        view_model.progress_bar_visible.connect(self._progress_bar.setVisible)
        view_model.progress_bar_range.connect(self._progress_bar.setRange)
        view_model.progress_bar_value.connect(self._progress_bar.setValue)

        # Usage label
        self._usage_label = _ClickableLabel()
        self._hbox.addWidget(self._usage_label)
        self._usage_label.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        self._usage_label.setVisible(False)
        self._usage_label.clicked.connect(self._on_usage_clicked)
        self._usage_clickable = False

        view_model.usage_status.connect(self._handle_usage_status_change)
        view_model.usage_text.connect(self._usage_label.setText)
        view_model.usage_tooltip.connect(self._usage_label.setToolTip)
        view_model.usage_visible.connect(self._usage_label.setVisible)
        view_model.usage_clickable.connect(self._set_usage_clickable)

    def _handle_usage_status_change(self, status: str) -> None:
        self._usage_label.setProperty("usageStatus", status)
        self._usage_label.style().unpolish(self._usage_label)
        self._usage_label.style().polish(self._usage_label)
        self._usage_label.update()

    def _on_label_click(self) -> None:
        if self._save_results_icon.isVisible():
            self.save_results_clicked.emit()
        elif self._upload_icon.isVisible():
            self.upload_clicked.emit()

    def _on_usage_clicked(self) -> None:
        if self._usage_clickable:
            self.usage_clicked.emit()

    def _set_usage_clickable(self, clickable: bool) -> None:
        self._usage_clickable = clickable
        if clickable:
            self._usage_label.setCursor(Qt.PointingHandCursor)
        else:
            self._usage_label.unsetCursor()


class _ClickableLabel(QLabel):
    clicked = Signal()

    def mousePressEvent(self, ev: QtGui.QMouseEvent) -> None:
        if ev.button() == Qt.LeftButton:
            self.clicked.emit()


def _load_icon(file_name: str) -> QPixmap:
    with importlib.resources.path(assets, file_name) as file_path:
        return QPixmap(str(file_path))
