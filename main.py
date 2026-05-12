"""
网络扫描器 - 程序入口
"""
import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from gui.main_window import MainWindow


def main():
    """主函数"""
    # 启用高DPI缩放
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)

    # 设置应用样式
    app.setStyle('Fusion')

    # 创建并显示主窗口
    window = MainWindow()
    window.show()

    # 连接清除按钮信号
    window.clear_btn.clicked.connect(window.clear_results)

    # 连接扫描按钮信号
    window.scan_btn.clicked.connect(window.start_scan)
    window.stop_btn.clicked.connect(window.stop_scan)

    # 运行应用
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()