import os
import sys
import json
import subprocess
import hashlib
import datetime
from pathlib import Path
import base64
import pefile  # Added for PE parsing
from PyQt6.QtGui import QFont, QPixmap, QColor
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
    QPlainTextEdit,
    QAbstractItemView,
    QTabWidget,
    QFormLayout,  # Added for properties layout
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

        # Define category colors
        self.category_colors = {
            "Network Communication": "#FFCCCC",      # Light red
            "File System Operations": "#CCFFCC",     # Light green
            "Registry Manipulation": "#CCCCFF",      # Light blue
            "Process/Thread Management": "#FFFFCC",  # Light yellow
            "Input Capture": "#FFCCFF",              # Light magenta
            "System Information Gathering": "#CCFFFF", # Light cyan
            "Anti-Analysis and Evasion": "#FFD700",  # Gold
            "Privilege Escalation": "#FFA07A",       # Light salmon
            "Service Manipulation": "#98FB98"        # Pale green
        }
        
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

        # Initialize properties dock widget
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
        self.properties_widget = QWidget()
        self.properties_layout = QFormLayout(self.properties_widget)
        properties_dock_widget.setWidget(self.properties_widget)

        self.parameters_dock_widget = QtAds.CDockWidget("Parameters: ")
        self.parameters_dock_widget.setMinimumSizeHintMode(
            QtAds.CDockWidget.eMinimumSizeHintMode.MinimumSizeHintFromDockWidget
        )
        self.parameters_dock_widget.resize(250, 150)
        self.parameters_dock_widget.setMinimumSize(200, 150)
        parameters_area = self.dock_manager.addDockWidget(
            QtAds.DockWidgetArea.BottomDockWidgetArea, self.parameters_dock_widget
        )
        self.menuView.addAction(self.parameters_dock_widget.toggleViewAction())
        self.parameters_table = QTableWidget()
        self.parameters_table.setColumnCount(3)
        self.parameters_table.setHorizontalHeaderLabels(["#", "Name", "Value"])
        self.parameters_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.parameters_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.parameters_table.itemSelectionChanged.connect(self.on_parameter_selected)
        self.parameters_dock_widget.setWidget(self.parameters_table)
        
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
        self.hex_text_edit = QPlainTextEdit()
        self.hex_text_edit.setReadOnly(True)
        self.hex_text_edit.setFont(QFont("Courier"))
        hex_buffer_dock_widget.setWidget(self.hex_text_edit)
        
        summary_dock_widget = QtAds.CDockWidget("Summary")
        summary_dock_widget.setMinimumSizeHintMode(
            QtAds.CDockWidget.eMinimumSizeHintMode.MinimumSizeHintFromDockWidget
        )
        summary_dock_widget.resize(250, 150)
        summary_dock_widget.setMinimumSize(200, 150)
        self.dock_manager.addDockWidget(
            QtAds.DockWidgetArea.BottomDockWidgetArea, summary_dock_widget
        )
        self.summary_tab_widget = QTabWidget()
        summary_dock_widget.setWidget(self.summary_tab_widget)
        self.menuView.addAction(summary_dock_widget.toggleViewAction())

    def open_monitor_dialog(self):
        dialog = MonitorProcessDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
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
        monitor_exe = "C:\\Users\\FlareVM\\Desktop\\Sample\\Sample1\\MonitoringApplication.exe"  # Update with actual path
        dll_path = "C:\\Users\\FlareVM\\Desktop\\Sample\\Sample1\\HookingDll.dll"  # Update with actual path
        
        filename = os.path.splitext(os.path.basename(process_path))[0]
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_filename = os.path.join(os.path.dirname(process_path), f"{filename}_{timestamp}_api_log.jsonl")
        
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
                "timestamp": timestamp,
                "log_file": log_filename,
                "properties": self.collect_file_properties(process_path)
            }
            
            self.running_processes.append(process_info)
            # Display properties immediately
            self.display_properties(process_info["properties"])
            list_item = QListWidgetItem(f"{timestamp} - {process_path}")
            self.process_list.addItem(list_item)
            process_info["list_item"] = list_item
            process.wait(float(runtime) if runtime else None)
            self.display_log_file(process_info["log_file"])
        except subprocess.TimeoutExpired:
            process.terminate()
            print("Process terminated after timeout.")           
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start process: {str(e)}")
            if process_info in self.running_processes:
                self.running_processes.remove(process_info)
                if process_info["list_item"]:
                    self.process_list.takeItem(self.process_list.row(process_info["list_item"]))

    def collect_file_properties(self, file_path):
        """Collect general properties of the file for display."""
        properties = {}

        # Basic file information
        properties["File Name"] = os.path.basename(file_path)
        properties["File Size"] = f"{os.path.getsize(file_path)} bytes"
        properties["File Type"] = "PE" if file_path.lower().endswith((".exe", ".dll")) else "Unknown"
        properties["File Path"] = file_path

        # File hashes
        with open(file_path, "rb") as f:
            data = f.read()
            properties["MD5"] = hashlib.md5(data).hexdigest()
            properties["SHA1"] = hashlib.sha1(data).hexdigest()
            properties["SHA256"] = hashlib.sha256(data).hexdigest()

        # PE-specific information (if applicable)
        if properties["File Type"] == "PE":
            try:
                pe = pefile.PE(file_path)
                if pe.FILE_HEADER.Machine == 0x14c:
                    properties["Architecture"] = "x32"
                elif pe.FILE_HEADER.Machine == 0x8664:
                    properties["Architecture"] = "x64"
                else:
                    properties["Architecture"] = "Unknown"
                    
                properties["Entry Point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                # sections_info = [f"{section.Name.decode().strip(chr(0))} ({section.SizeOfRawData} bytes)" for section in pe.sections]
                properties["Sections"] = "\n".join(
                    [f"{section.Name.decode().strip(chr(0))} ({section.SizeOfRawData} bytes)" for section in pe.sections]
                )
                # properties["Imports"] = "\n".join(
                #     [f"{dll.dll.decode()}: {', '.join(imp.name.decode() for imp in dll.imports if imp.name)}"
                #     for dll in pe.DIRECTORY_ENTRY_IMPORT]
                # ) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else "None"
                # properties["Exports"] = "\n".join(
                #     [exp.name.decode() for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols]
                # ) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else "None"
            except Exception as e:
                properties["PE Error"] = f"Failed to parse PE: {str(e)}"

        return properties

    def display_properties(self, properties):
        """Display file properties in the properties dock widget."""
        # Clear existing content
        for i in reversed(range(self.properties_layout.count())):
            self.properties_layout.itemAt(i).widget().setParent(None)
        
        # Add new properties
        for key, value in properties.items():
            label = QLabel(f"{key}:")
            value_label = QLabel(str(value))
            value_label.setWordWrap(True)  # Wrap long text like hashes or sections
            self.properties_layout.addRow(label, value_label)

    def parse_log_message(self, log_message):
        params = {}
        parts = log_message.split(', ')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                params[key.strip()] = value.strip()
        return params

    def switch_process(self, item):
        timestamp = item.text().split(" - ")[0]
        self.current_timestamp = timestamp
        self.clear_log_api_widget()
        for process_info in self.running_processes:
            if process_info["timestamp"] == self.current_timestamp:
                # Display properties when switching processes
                self.display_properties(process_info["properties"])
                if process_info["log_file"] and os.path.exists(process_info["log_file"]):
                    self.display_log_file(process_info["log_file"])
                    self.display_properties(process_info["properties"])
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
                table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
                table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
                table.itemSelectionChanged.connect(self.on_log_row_selected)
                
                if category in self.category_colors:
                    color = self.category_colors[category]
                    table.setStyleSheet(f"QTableView {{ background-color: {color}; }}")
                    pixmap = QPixmap(16, 16)
                    pixmap.fill(QColor(color))
                    icon = QIcon(pixmap)
                    section.toggleButton.setIcon(icon)
                else:
                    table.setStyleSheet("QTableView { background-color: #FFFFFF; }")
                
                section_layout = QVBoxLayout()
                section_layout.addWidget(table)
                section.setContentLayout(section_layout)
                self.log_api_layout.addWidget(section)

        # Define summary structure
        summary_structure = {
            "File System Actions": {
                "Files Read": [
                    ("ReadFile", "hFile"), ("MoveFileW", "lpExistingFileName"),
                    ("CopyFileExW", "lpExistingFileName"), ("FtpPutFileA", "lpszLocalFile"),
                    ("FtpPutFileW", "lpszLocalFile")
                ],
                "Files Written": [
                    ("WriteFile", "hFile"), ("MoveFileW", "lpNewFileName"),
                    ("CopyFileExW", "lpNewFileName"), ("URLDownloadToFileW", "szFileName"),
                    ("URLDownloadToFileA", "szFileName"), ("URLDownloadToCacheFileA", "szFileName"),
                    ("FtpPutFileA", "lpszNewRemoteFile"), ("FtpPutFileW", "lpszNewRemoteFile")
                ],
                "Files Deleted": [("DeleteFileW", "lpFileName")]
            },
            "Registry Actions": {
                "Registry keys set": [
                    ("RegSetValueExA", "hKey"), ("RegSetValueExW", "hKey"),
                    ("RegCreateKeyExA", "phkResult"), ("RegCreateKeyExW", "phkResult")
                ],
                "Registry keys deleted": [
                    ("RegDeleteKeyW", "hKey"), ("RegDeleteKeyExA", "hKey"),
                    ("RegDeleteKeyExW", "hKey")
                ]
            },
            "Network": {
                "C2C server": [
                    ("connect", "addr"), ("WSAConnect", "addr"), ("send", "addr"), ("recv", "addr"),
                    ("getaddrinfo", "nodeName"), ("GetAddrInfoW", "nodeName"),
                    ("URLDownloadToFileW", "szURL"), ("InternetReadFile", "hFile"),
                    ("InternetReadFileExA", "hFile"), ("InternetWriteFile", "hFile"),
                    ("URLDownloadToFileA", "szURL"), ("URLDownloadToCacheFileA", "szURL"),
                    ("URLOpenBlockingStreamA", "szURL"), ("URLOpenStreamA", "szURL"),
                    ("WinHttpConnect", "pswzServerName"), ("WinHttpOpenRequest", "url"),
                    ("HttpOpenRequestA", "url"), ("HttpOpenRequestW", "url"),
                    ("HttpSendRequestA", "hRequest"), ("HttpSendRequestW", "hRequest"),
                    ("HttpSendRequestExA", "hRequest"), ("HttpSendRequestExW", "hRequest"),
                    ("InternetOpenUrlA", "lpszUrl"), ("ShellExecuteExW", "lpFile")
                ]
            },
            "Process Actions": {
                "Processes opened": [("OpenProcess", "processName")],
                "Processed created": [
                    ("CreateProcessA", "lpApplicationName"), ("CreateProcessA", "lpCommandLine"),
                    ("CreateProcessW", "lpApplicationName"), ("CreateProcessW", "lpCommandLine")
                ],
                "Processes memory read": [("ReadProcessMemory", "hProcess")],
                "Processes memory written": [
                    ("WriteProcessMemory", "hProcess"), ("VirtualAllocEx", "hProcess")
                ],
                "Processes changed protection": [("VirtualProtectEx", "hProcess")],
                "Processes being created thread": [("CreateRemoteThread", "hProcess")],
                "Process being resumed/suspended thread": [
                    ("ResumeThread", "processName"), ("SuspendThread", "processName")
                ]
            },
            "Service Actions": {
                "Service created": [
                    ("CreateServiceA", "lpServiceName"), ("CreateServiceA", "lpDisplayName"),
                    ("CreateServiceA", "lpBinaryPathName"), ("CreateServiceA", "lpServiceStartName"),
                    ("CreateServiceW", "lpServiceName"), ("CreateServiceW", "lpDisplayName"),
                    ("CreateServiceW", "lpBinaryPathName"), ("CreateServiceW", "lpServiceStartName")
                ],
                "Service started": [("StartServiceA", "hService"), ("StartServiceW", "hService")]
            },
            "Mutex Actions": {
                "Mutexes created": [("CreateMutexW", "lpName")]
            }
        }

        # Extract unique values from logs
        summary_data = {tab: {section: set() for section in sections} for tab, sections in summary_structure.items()}
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        api_name = log_entry["api_name"]
                        params = self.parse_log_message(log_entry["log_message"])
                        for tab, sections in summary_structure.items():
                            for section, api_params in sections.items():
                                for api, param in api_params:
                                    if api_name == api and param in params and params[param] != "null":
                                        value = params[param]
                                        if api in ["getaddrinfo", "GetAddrInfoW"] and param == "nodeName":
                                            service_name = params.get("serviceName", "")
                                            value = f"{value}:{service_name}" if service_name else value
                                        elif api == "WinHttpConnect" and param == "pswzServerName":
                                            port = params.get("nServerPort", "")
                                            value = f"{value}:{port}" if port else value
                                        summary_data[tab][section].add(value)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass

        # Populate summary tabs
        self.summary_tab_widget.clear()
        for tab_name, sections in summary_data.items():
            tab_widget = QWidget()
            tab_layout = QVBoxLayout(tab_widget)
            for section_name, values in sections.items():
                if values:
                    section_label = QLabel(f"• {section_name}")
                    section_label.setStyleSheet("font-weight: bold;")
                    tab_layout.addWidget(section_label)
                    values_text = QPlainTextEdit()
                    values_text.setPlainText("\n".join(sorted(values)))
                    values_text.setReadOnly(True)
                    tab_layout.addWidget(values_text)
            tab_layout.addStretch()
            if any(values for values in sections.values()):
                self.summary_tab_widget.addTab(tab_widget, tab_name)

        self.log_api_layout.addStretch()
    
    def format_hex_dump(self, data):
        hex_dump = ""
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            hex_dump += f'{i:04X}:  {hex_part:<47}  {ascii_part}\n'
        return hex_dump

    def display_hex_dump(self, hex_dump):
        self.hex_text_edit.setPlainText(hex_dump)

    def clear_hex_dump(self):
        self.hex_text_edit.clear()
    
    def on_parameter_selected(self):
        selected_items = self.parameters_table.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            value_item = self.parameters_table.item(row, 2)
            if value_item:
                value = value_item.text()
                try:
                    binary_data = base64.b64decode(value)
                    hex_dump = self.format_hex_dump(binary_data)
                    self.display_hex_dump(hex_dump)
                except Exception:
                    self.clear_hex_dump()
        else:
            self.clear_hex_dump()
    
    def parse_and_display_parameters(self, log_message):
        parameters = []
        parts = log_message.split(', ')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                parameters.append((key.strip(), value.strip()))
        
        self.parameters_table.setRowCount(len(parameters))
        for i, (name, value) in enumerate(parameters):
            self.parameters_table.setItem(i, 0, QTableWidgetItem(str(i + 1)))
            self.parameters_table.setItem(i, 1, QTableWidgetItem(name))
            self.parameters_table.setItem(i, 2, QTableWidgetItem(value))
        self.parameters_table.resizeColumnsToContents()
     
    def on_log_row_selected(self):
        table = self.sender()
        if isinstance(table, QTableWidget):
            selected_items = table.selectedItems()
            if selected_items:
                row = selected_items[0].row()
                api_name = table.item(row, 2).text()
                log_message = table.item(row, 3).text()
                self.parse_and_display_parameters(log_message)
                self.parameters_dock_widget.setWindowTitle(f"Parameters: {api_name}")
            else:
                self.parameters_table.setRowCount(0)
                self.parameters_dock_widget.setWindowTitle("Parameters: ")
                
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