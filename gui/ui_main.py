"""
UI设计模块 - 定义GUI界面的布局和组件
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QTextEdit, QProgressBar,
                             QGroupBox, QFormLayout, QCheckBox)
from PyQt5.QtCore import Qt


class UiMain:
    """UI界面设计类"""

    def setup_ui(self, main_window):
        """
        设置UI界面布局

        Args:
            main_window: QMainWindow实例
        """
        main_window.setWindowTitle('网络扫描器')
        main_window.resize(900, 700)

        # 中心部件
        central_widget = QWidget()
        main_window.setCentralWidget(central_widget)

        # 主布局
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)

        # === 扫描配置区域 ===
        config_group = QGroupBox('扫描配置')
        config_layout = QFormLayout()

        # IP地址输入
        self.ip_label = QLabel('目标IP/范围:')
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText('例如: 192.168.1.1 或 192.168.1.1-10')
        config_layout.addRow(self.ip_label, self.ip_input)

        # 端口范围输入
        self.port_label = QLabel('端口范围:')
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText('例如: 80, 443, 22 或 1-1024')
        self.port_input.setText('1-1024')
        config_layout.addRow(self.port_label, self.port_input)

        # 高级选项折叠区域
        self.advanced_widget = QWidget()
        advanced_layout = QFormLayout(self.advanced_widget)

        # 超时设置
        self.timeout_label = QLabel('超时时间(秒):')
        self.timeout_input = QLineEdit()
        self.timeout_input.setText('1')
        self.timeout_input.setMaximumWidth(100)
        advanced_layout.addRow(self.timeout_label, self.timeout_input)

        # 线程数设置
        self.threads_label = QLabel('线程数:')
        self.threads_input = QLineEdit()
        self.threads_input.setText('50')
        self.threads_input.setMaximumWidth(100)
        advanced_layout.addRow(self.threads_label, self.threads_input)

        config_layout.addRow(self.advanced_widget)

        config_group.setLayout(config_layout)
        main_layout.addWidget(config_group)

        # === 控制按钮区域 ===
        control_layout = QHBoxLayout()

        self.scan_btn = QPushButton('开始扫描')
        self.scan_btn.setMinimumHeight(40)
        self.stop_btn = QPushButton('停止扫描')
        self.stop_btn.setMinimumHeight(40)
        self.stop_btn.setEnabled(False)
        self.clear_btn = QPushButton('清除结果')
        self.clear_btn.setMinimumHeight(40)

        control_layout.addWidget(self.scan_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.clear_btn)
        control_layout.addStretch()

        main_layout.addLayout(control_layout)

        # === 进度条 ===
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumHeight(25)
        self.progress_bar.setTextVisible(True)
        main_layout.addWidget(self.progress_bar)

        # === 结果显示区域 ===
        result_group = QGroupBox('扫描结果')
        result_layout = QVBoxLayout()

        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setStyleSheet('''
            QTextEdit {
                background-color: #1e1e1e;
                color: #00ff00;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
            }
        ''')
        result_layout.addWidget(self.result_text)

        result_group.setLayout(result_layout)
        main_layout.addWidget(result_group, 1)

        # === 日志显示区域 ===
        log_group = QGroupBox('日志信息')
        log_layout = QVBoxLayout()

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(120)
        self.log_text.setStyleSheet('''
            QTextEdit {
                background-color: #f5f5f5;
                color: #333333;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
            }
        ''')
        log_layout.addWidget(self.log_text)

        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)

    def update_log(self, message, level='info'):
        """
        更新日志显示

        Args:
            message: 日志消息
            level: 日志级别 (info/warning/error)
        """
        color_map = {
            'info': '#333333',
            'warning': '#ff8800',
            'error': '#ff0000'
        }
        color = color_map.get(level, '#333333')
        self.log_text.append(f'<span style="color:{color}">[{level.upper()}] {message}</span>')

    def update_result(self, message):
        """
        更新结果文本

        Args:
            message: 结果消息
        """
        self.result_text.append(message)

    def clear_result(self):
        """清除结果显示"""
        self.result_text.clear()

    def clear_log(self):
        """清除日志显示"""
        self.log_text.clear()