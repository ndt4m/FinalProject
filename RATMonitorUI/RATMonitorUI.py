import os
import sys

import PyQt6Ads as QtAds
from PyQt6 import uic
from PyQt6.QtCore import QSignalBlocker, Qt, QParallelAnimationGroup, QPropertyAnimation, QAbstractAnimation
from PyQt6.QtGui import QAction, QCloseEvent
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QInputDialog,
    QLabel,
    QSizePolicy,
    QTableWidget,
    QWidgetAction,
    QWidget,
    QToolButton,
    QFrame,
    QScrollArea,
    QGridLayout,
    QVBoxLayout,
    QPushButton
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

        # start out collapsed
        self.contentArea.setMaximumHeight(0)
        self.contentArea.setMinimumHeight(0)

        # let the entire widget grow and shrink with its content
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
        self.setTitle(title)  # Set the title after initialization

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

class CMainWindow(MainWindowUI, MainWindowBase):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setupUi(self)

        QtAds.CDockManager.setConfigFlag(
            QtAds.CDockManager.eConfigFlag.OpaqueSplitterResize, True
        )
        QtAds.CDockManager.setConfigFlag(
            QtAds.CDockManager.eConfigFlag.FocusHighlighting, True
        )
        self.dock_manager = QtAds.CDockManager(self)

        vbox = QVBoxLayout()
        table = QTableWidget()
        table.setColumnCount(3)
        table.setRowCount(10)
        section = Section("Network Communication", animationDuration=100, parent=self)
        anyLayout = QVBoxLayout()
        anyLayout.addWidget(table)
        section.setContentLayout(anyLayout)
        vbox.addWidget(section)
        
        table = QTableWidget()
        table.setColumnCount(3)
        table.setRowCount(10)
        section = Section("File System Operations", animationDuration=100, parent=self)
        anyLayout = QVBoxLayout()
        anyLayout.addWidget(table)
        section.setContentLayout(anyLayout)
        vbox.addWidget(section)
        
        log_api_widget = QWidget()
        log_api_widget.setLayout(vbox)
        central_dock_widget = QtAds.CDockWidget("CentralWidget")
        central_dock_widget.setWidget(log_api_widget)
        central_dock_widget.setFeature(QtAds.CDockWidget.DockWidgetFeature.NoTab, True)
        central_dock_area = self.dock_manager.setCentralWidget(central_dock_widget)
        
        monitored_process_dock_widget = QtAds.CDockWidget("Monitored Process")
        monitored_process_dock_widget.setMinimumSizeHintMode(
            QtAds.CDockWidget.eMinimumSizeHintMode.MinimumSizeHintFromDockWidget
        )
        monitored_process_dock_widget.resize(250, 150)
        monitored_process_dock_widget.setMinimumSize(200, 150)
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

    def closeEvent(self, event: QCloseEvent):
        # Delete dock manager here to delete all floating widgets. This ensures
        # that all top level windows of the dock manager are properly closed
        self.dock_manager.deleteLater()
        super().closeEvent(event)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    w = CMainWindow()
    w.show()
    app.exec()
