import os
import sys
import json
import subprocess
import datetime
from pathlib import Path
from PyQt6.QtCore import QTimer

import PyQt6Ads as QtAds
from PyQt6 import uic
from PyQt6.QtCore import QSignalBlocker, Qt, QParallelAnimationGroup, QPropertyAnimation, QAbstractAnimation
from PyQt6.QtGui import QAction, QCloseEvent, QIcon, QKeySequence
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGridLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QWidgetAction,
    QWidget,
    QToolButton,
    QFrame,
    QScrollArea,
    QVBoxLayout,
    QPushButton,
    QMessageBox,
    QToolBar,
    QListWidget,
    QListWidgetItem,
)

UI_FILE = os.path.join(os.path.dirname(__file__), "RATMonitorUI.ui")
MainWindowUI, MainWindowBase = uic.loadUiType(UI_FILE)

class Section(QWidget):
    def __init__(self, title, animationDuration=100, parent=None):
        super().__init__(parent)
        self.animationDuration = animationDuration
        self.toggleButton = QToolButton(self)
        self.headerLine = QFrame(self)
        self.toggleAnimation = QParallelAnimationGroup(self)
        self.contentArea = QScrollArea(self)
        self.mainLayout = QGridLayout(self)

        self.toggleButton.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.toggleButton.setArrowType(Qt.ArrowType.RightArrow)
        self.toggleButton.setCheckable(True)
        self.toggleButton.setChecked(False)

        self.headerLine.setFrameShape(QFrame.Shape.HLine)
        self.headerLine.setFrameShadow(QFrame.Shadow.Sunken)
        self.headerLine.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)

        self.contentArea.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.contentArea.setMaximumHeight(0)
        self.contentArea.setMinimumHeight(0)

        self.toggleAnimation.addAnimation(QPropertyAnimation(self, b"minimumHeight"))
        self.toggleAnimation.addAnimation(QPropertyAnimation(self, b"maximumHeight"))
        self.toggleAnimation.addAnimation(QPropertyAnimation(self.contentArea, b"maximumHeight"))

        self.mainLayout.setVerticalSpacing(0)
        self.mainLayout.setContentsMargins(0, 0, 0, 0)

        row = 0
        self.mainLayout.addWidget(self.toggleButton, row, 0, 1, 1)
        self.mainLayout.addWidget(self.headerLine, row, 2, 1, 1)
        self.mainLayout.addWidget(self.contentArea, row + 1, 0, 1, 3)
        self.setLayout(self.mainLayout)

        self.toggleButton.toggled.connect(self.toggle)
        self.setTitle(title)

    def setTitle(self, title):
        self.toggleButton.setText(title)

    def setContentLayout(self, contentLayout):
        layout = self.contentArea.layout()
        if layout:
            del layout
        self.contentArea.setLayout(contentLayout)
        collapsedHeight = self.sizeHint().height() - self.contentArea.maximumHeight()
        contentHeight = contentLayout.sizeHint().height()
        for i in range(0, self.toggleAnimation.animationCount() - 1):
            SectionAnimation = self.toggleAnimation.animationAt(i)
            SectionAnimation.setDuration(self.animationDuration)
            SectionAnimation.setStartValue(collapsedHeight)
            SectionAnimation.setEndValue(collapsedHeight + contentHeight)
        contentAnimation = self.toggleAnimation.animationAt(self.toggleAnimation.animationCount() - 1)
        contentAnimation.setDuration(self.animationDuration)
        contentAnimation.setStartValue(0)
        contentAnimation.setEndValue(contentHeight)

    def toggle(self, collapsed):
        if collapsed:
            self.toggleButton.setArrowType(Qt.ArrowType.DownArrow)
            self.toggleAnimation.setDirection(QAbstractAnimation.Direction.Forward)
        else:
            self.toggleButton.setArrowType(Qt.ArrowType.RightArrow)
            self.toggleAnimation.setDirection(QAbstractAnimation.Direction.Backward)
        self.toggleAnimation.start()

class MonitorProcessDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Monitor New Process")
        self.setup_ui()

    def setup_ui(self):
        layout = QGridLayout(self)
        description = QLabel(
            "Enter the location of the file, the arguments (optional), "
            "and the startup directory to start the monitoring process."
        )
        description.setWordWrap(True)
        layout.addWidget(description, 0, 0, 1, 3)

        layout.addWidget(QLabel("Process:"), 1, 0)
        self.process_input = QLineEdit()
        layout.addWidget(self.process_input, 1, 1)
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_file)
        layout.addWidget(browse_button, 1, 2)

        layout.addWidget(QLabel("Arguments:"), 2, 0)
        self.args_input = QLineEdit()
        layout.addWidget(self.args_input, 2, 1, 1, 2)

        layout.addWidget(QLabel("Start in:"), 3, 0)
        self.start_dir_input = QLineEdit()
        layout.addWidget(self.start_dir_input, 3, 1, 1, 2)

        layout.addWidget(QLabel("Run time (seconds, empty for infinite):"), 4, 0)
        self.runtime_input = QLineEdit()
        layout.addWidget(self.runtime_input, 4, 1, 1, 2)

        self.button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box, 5, 0, 1, 3)
        self.resize(800, 200)
        self.setLayout(layout)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Process File",
            "",
            "Executables (*.exe);;All Files (*)"
        )
        if file_path:
            self.process_input.setText(str(Path(file_path)))
            start_dir = str(Path(file_path).parent)
            self.start_dir_input.setText(start_dir)

    def validate_inputs(self):
        process_path = self.process_input.text().strip()
        start_dir = self.start_dir_input.text().strip()
        runtime = self.runtime_input.text().strip()

        if not process_path or not os.path.isfile(process_path):
            return False, "Please select a valid executable file."

        if start_dir and not os.path.isdir(start_dir):
            return False, "Please enter a valid startup directory."

        if runtime:
            try:
                runtime_val = float(runtime)
                if runtime_val <= 0:
                    return False, "Run time must be a positive number or empty for infinite."
            except ValueError:
                return False, "Run time must be a number or empty for infinite."

        return True, ""

    def get_inputs(self):
        return {
            "process": self.process_input.text().strip(),
            "arguments": self.args_input.text().strip(),
            "start_dir": self.start_dir_input.text().strip(),
            "runtime": self.runtime_input.text().strip()
        }

class CMainWindow(MainWindowUI, MainWindowBase):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.running_processes = []
        self.current_pid = None

        QtAds.CDockManager.setConfigFlag(
            QtAds.CDockManager.eConfigFlag.OpaqueSplitterResize, True
        )
        QtAds.CDockManager.setConfigFlag(
            QtAds.CDockManager.eConfigFlag.FocusHighlighting, True
        )
        self.dock_manager = QtAds.CDockManager(self)

        # Initialize log_api_widget
        self.log_api_widget = QWidget()
        self.log_api_layout = QVBoxLayout(self.log_api_widget)
        self.log_api_layout.addWidget(QLabel("No process selected or log file loaded."))
        self.log_api_layout.addStretch()

        central_dock_widget = QtAds.CDockWidget("CentralWidget")
        central_dock_widget.setWidget(self.log_api_widget)
        central_dock_widget.setFeature(QtAds.CDockWidget.DockWidgetFeature.NoTab, True)
        central_dock_area = self.dock_manager.setCentralWidget(central_dock_widget)

        monitored_process_dock_widget = QtAds.CDockWidget("Monitored Process")
        monitored_process_dock_widget.setMinimumSizeHintMode(
            QtAds.CDockWidget.eMinimumSizeHintMode.MinimumSizeHintFromDockWidget
        )
        monitored_process_dock_widget.resize(250, 150)
        monitored_process_dock_widget.setMinimumSize(200, 150)

        monitored_widget = QWidget()
        monitored_layout = QVBoxLayout(monitored_widget)
        monitored_toolbar = QToolBar()
        monitored_layout.addWidget(monitored_toolbar)

        self.actionMonitoring_New_Process.triggered.connect(self.open_monitor_dialog)
        self.actionMonitoring_New_Process.setShortcut(QKeySequence("Ctrl+m"))
        monitored_toolbar.addAction(self.actionMonitoring_New_Process)

        self.actionStop_Monitoring.setToolTip("Stop the selected process")
        self.actionStop_Monitoring.triggered.connect(self.stop_monitoring)
        monitored_toolbar.addAction(self.actionStop_Monitoring)

        self.actionRemove_process = QAction("Remove Process", self)
        self.actionRemove_process.setToolTip("Remove the selected process from the list")
        self.actionRemove_process.triggered.connect(self.remove_process)
        monitored_toolbar.addAction(self.actionRemove_process)

        self.process_list = QListWidget()
        self.process_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        self.process_list.itemClicked.connect(self.switch_process)
        monitored_layout.addWidget(self.process_list)

        monitored_process_dock_widget.setWidget(monitored_widget)
        self.dock_manager.addDockWidget(
            QtAds.DockWidgetArea.LeftDockWidgetArea, monitored_process_dock_widget
        )
        self.menuView.addAction(monitored_process_dock_widget.toggleViewAction())

        properties_dock_widget = QtAds.CDockWidget("Properties")
        properties_dock_widget.setMinimumSizeHintMode(
            QtAds.CDockWidget.eMinimumSizeHintMode.MinimumSizeHintFromDockWidget
        )
        properties_dock_widget.resize(250, 150)
        properties_dock_widget.setMinimumSize(200, 150)
        self.dock_manager.addDockWidget(
            QtAds.DockWidgetArea.LeftDockWidgetArea,
            properties_dock_widget,
            central_dock_area,
        )
        self.menuView.addAction(properties_dock_widget.toggleViewAction())

        parameters_dock_widget = QtAds.CDockWidget("Parameters: ")
        parameters_dock_widget.setMinimumSizeHintMode(
            QtAds.CDockWidget.eMinimumSizeHintMode.MinimumSizeHintFromDockWidget
        )
        parameters_dock_widget.resize(250, 150)
        parameters_dock_widget.setMinimumSize(200, 150)
        parameters_area = self.dock_manager.addDockWidget(
            QtAds.DockWidgetArea.BottomDockWidgetArea, parameters_dock_widget
        )
        self.menuView.addAction(parameters_dock_widget.toggleViewAction())

        hex_buffer_dock_widget = QtAds.CDockWidget("Hex Buffer")
        hex_buffer_dock_widget.setMinimumSizeHintMode(
            QtAds.CDockWidget.eMinimumSizeHintMode.MinimumSizeHintFromDockWidget
        )
        hex_buffer_dock_widget.resize(250, 150)
        hex_buffer_dock_widget.setMinimumSize(200, 150)
        self.dock_manager.addDockWidget(
            QtAds.DockWidgetArea.RightDockWidgetArea, hex_buffer_dock_widget, parameters_area
        )
        self.menuView.addAction(hex_buffer_dock_widget.toggleViewAction())

        summary_dock_widget = QtAds.CDockWidget("Summary")
        summary_dock_widget.setMinimumSizeHintMode(
            QtAds.CDockWidget.eMinimumSizeHintMode.MinimumSizeHintFromDockWidget
        )
        summary_dock_widget.resize(250, 150)
        summary_dock_widget.setMinimumSize(200, 150)
        self.dock_manager.addDockWidget(
            QtAds.DockWidgetArea.BottomDockWidgetArea, summary_dock_widget
        )
        self.menuView.addAction(summary_dock_widget.toggleViewAction())

    def open_monitor_dialog(self):
        dialog = MonitorProcessDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # self.display_log_file("C:\\Users\\HP\\Documents\\FinalProject\\FinalProject\\MonitoringApplication\\Release\\adddd.jsonl")
            # return
            inputs = dialog.get_inputs()
            is_valid, error_message = dialog.validate_inputs()
            if not is_valid:
                QMessageBox.critical(self, "Invalid Input", error_message)
                self.open_monitor_dialog()
                return
            self.start_monitoring_process(
                inputs["process"],
                inputs["arguments"],
                inputs["start_dir"],
                inputs["runtime"]
            )

    def start_monitoring_process(self, process_path, arguments, start_dir, runtime):
        monitor_exe = "MonitoringApplication\\Release\\MonitoringApplication.exe"
        dll_path = "MonitoringApplication\\Release\\HookingDll.dll"
        
        # Generate log file name
        filename = os.path.splitext(os.path.basename(process_path))[0]
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_filename = f"{filename}_{timestamp}_api_log.jsonl"
        
        cmd = [monitor_exe, process_path, dll_path, log_filename]
        if arguments:
            cmd.extend(arguments.split())
            
        try:
            process = subprocess.Popen(
                cmd,
                cwd=start_dir if start_dir else None,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            process_info = {
                "process": process,
                "path": process_path,
                "timer": None,
                "list_item": None,
                "pid": process.pid,
                "log_file": log_filename
            }
            self.running_processes.append(process_info)
            process.wait(float(runtime) if runtime else None)
            list_item = QListWidgetItem(f"PID: {process.pid} - {process_path}")
            self.process_list.addItem(list_item)
            process_info["list_item"] = list_item
            
        except subprocess.TimeoutExpired:
            process.terminate()
            print("Process terminated after timeout.")           
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start process: {str(e)}")
            if process_info in self.running_processes:
                self.running_processes.remove(process_info)
                if process_info["list_item"]:
                    self.process_list.takeItem(self.process_list.row(process_info["list_item"]))

    def on_monitoring_finished(self, process_info):
        log_file = process_info["log_file"]
        if self.current_pid == process_info["pid"]:
            self.clear_log_api_widget()
            if log_file and os.path.exists(log_file):
                self.display_log_file(log_file)
            else:
                self.log_api_layout.addWidget(QLabel("No log file available for this process."))
                self.log_api_layout.addStretch()

    def switch_process(self, item):
        pid_text = item.text().split(" - ")[0].replace("PID: ", "")
        self.current_pid = int(pid_text)
        self.clear_log_api_widget()
        for process_info in self.running_processes:
            if process_info["pid"] == self.current_pid:
                if process_info["log_file"] and os.path.exists(process_info["log_file"]):
                    self.display_log_file(process_info["log_file"])
                else:
                    self.log_api_layout.addWidget(QLabel("No log file available for this process."))
                    self.log_api_layout.addStretch()
                break

    def clear_log_api_widget(self):
        while self.log_api_layout.count():
            child = self.log_api_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def display_log_file(self, log_file):
        self.clear_log_api_widget()
        api_categories = {
            "Network Communication": [
                "socket", "connect", "WSAConnect", "send", "recv", "getaddrinfo", "GetAddrInfoW",
                "URLDownloadToFileW", "InternetReadFile", "InternetWriteFile", "URLDownloadToFileA",
                "URLDownloadToCacheFileA", "URLOpenBlockingStreamA", "URLOpenStreamA", "WinHttpConnect",
                "WinHttpOpenRequest", "WinHttpOpen", "FtpPutFileA", "FtpPutFileW", "HttpOpenRequestA",
                "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW", "HttpSendRequestExA",
                "HttpSendRequestExW", "InternetOpenA", "InternetOpenW", "InternetOpenUrlA",
                "InternetReadFileExA", "ShellExecuteExW"
            ],
            "File System Operations": ["ReadFile", "WriteFile", "DeleteFileW", "MoveFileW", "CopyFileExW"],
            "Registry Manipulation": [
                "RegSetValueExA", "RegSetValueExW", "RegDeleteKeyW", "RegDeleteKeyExA",
                "RegDeleteKeyExW", "RegCreateKeyExA", "RegCreateKeyExW"
            ],
            "Process/Thread Management": [
                "CreateProcessW", "CreateProcessA", "OpenProcess", "WriteProcessMemory",
                "ReadProcessMemory", "CreateRemoteThread", "VirtualAllocEx", "VirtualProtectEx",
                "ResumeThread", "SuspendThread"
            ],
            "Input Capture": ["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState"],
            "System Information Gathering": [
                "GetComputerNameW", "GetLocaleInfoW", "GetSystemInfo", "GetUserNameA", "GetUserNameW"
            ],
            "Anti-Analysis and Evasion": [
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "FindWindowA", "FindWindowW",
                "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "CreateMutexW"
            ],
            "Privilege Escalation": ["AdjustTokenPrivileges"],
            "Service Manipulation": ["CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW"]
        }
        logs_by_category = {cat: [] for cat in api_categories}
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        api_name = log_entry["api_name"]
                        for category, apis in api_categories.items():
                            if api_name in apis:
                                logs_by_category[category].append(log_entry)
                                break
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            self.log_api_layout.addWidget(QLabel(f"Log file {log_file} not found."))
            self.log_api_layout.addStretch()
            return
        for category, logs in logs_by_category.items():
            if logs:
                section = Section(category, animationDuration=100, parent=self.log_api_widget)
                table = QTableWidget()
                table.setRowCount(len(logs))
                table.setColumnCount(4)
                table.setHorizontalHeaderLabels(["#", "Timestamp", "API Name", "Log Message"])
                table.horizontalHeader().setStretchLastSection(True)
                for i, log in enumerate(logs):
                    table.setItem(i, 0, QTableWidgetItem(str(i + 1)))
                    table.setItem(i, 1, QTableWidgetItem(log["timestamp"]))
                    table.setItem(i, 2, QTableWidgetItem(log["api_name"]))
                    table.setItem(i, 3, QTableWidgetItem(log["log_message"]))
                table.resizeColumnsToContents()
                section_layout = QVBoxLayout()
                section_layout.addWidget(table)
                section.setContentLayout(section_layout)
                self.log_api_layout.addWidget(section)
        self.log_api_layout.addStretch()

    def terminate_process(self, process_info):
        process = process_info["process"]
        list_item = process_info["list_item"]
        try:
            process.terminate()
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        except Exception as e:
            QMessageBox.warning(self, "Warning", f"Failed to terminate process: {str(e)}")
        finally:
            if process_info in self.running_processes:
                self.running_processes.remove(process_info)

    def stop_monitoring(self):
        selected_items = self.process_list.selectedItems()
        if selected_items:
            selected_item = selected_items[0]
            for process_info in self.running_processes[:]:
                if process_info["list_item"] == selected_item:
                    self.terminate_process(process_info)
                    break
        else:
            for process_info in self.running_processes[:]:
                self.terminate_process(process_info)

    def remove_process(self):
        selected_items = self.process_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select a process to remove.")
            return
        selected_item = selected_items[0]
        for process_info in self.running_processes[:]:
            if process_info["list_item"] == selected_item:
                QMessageBox.warning(self, "Warning", "Cannot remove a running process. Stop it first.")
                return
        self.process_list.takeItem(self.process_list.row(selected_item))

    def closeEvent(self, event: QCloseEvent):
        for process_info in self.running_processes[:]:
            self.terminate_process(process_info)
        self.dock_manager.deleteLater()
        super().closeEvent(event)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = CMainWindow()
    w.show()
    app.exec()