"""
主窗口模块 - 实现主窗口逻辑和扫描功能
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt5.QtWidgets import QMainWindow, QMessageBox, QApplication
from PyQt5.QtCore import QThread, pyqtSignal
from gui.ui_main import UiMain
from core.logger import log
from core.host_scan import scan_hosts, parse_ip_range
from core.port_scan import scan_ports


class ScanThread(QThread):
    """扫描线程 - 在后台执行扫描任务"""

    progress_updated = pyqtSignal(int, int, int)  # progress, scanned, total
    log_message = pyqtSignal(str, str)  # message, level
    result_ready = pyqtSignal(str)  # 单条结果文本

    def __init__(self, host, port_range, timeout, max_workers):
        super().__init__()
        self.host = host
        self.port_range = port_range
        self.timeout = timeout
        self.max_workers = max_workers
        self._stop_flag = False

    def stop(self):
        """请求停止扫描"""
        self._stop_flag = True

    def run(self):
        """执行扫描"""
        results = []

        try:
            # 阶段1: 主机扫描
            self.log_message.emit(f"开始主机发现: {self.host}", 'info')

            def host_progress(progress, scanned, total):
                if not self._stop_flag:
                    self.progress_updated.emit(
                        int(progress / 2),
                        scanned,
                        total
                    )

            alive_hosts = scan_hosts(
                self.host,
                max_workers=self.max_workers,
                timeout=self.timeout,
                progress_callback=host_progress
            )

            if self._stop_flag:
                self.log_message.emit("扫描已停止", 'warning')
                return

            if not alive_hosts:
                self.log_message.emit("未发现存活主机", 'warning')
                return

            self.log_message.emit(f"发现 {len(alive_hosts)} 个存活主机", 'info')

            # 阶段2: 端口扫描
            for idx, host_ip in enumerate(alive_hosts):
                if self._stop_flag:
                    break

                self.log_message.emit(f"正在扫描主机: {host_ip}", 'info')

                def port_progress(progress, scanned, total):
                    if not self._stop_flag:
                        base_progress = 50
                        per_host_progress = 50 / len(alive_hosts)
                        self.progress_updated.emit(
                            int(base_progress + per_host_progress * (idx + progress / 100)),
                            scanned,
                            total
                        )

                open_ports = scan_ports(
                    host_ip,
                    self.port_range,
                    max_workers=self.max_workers,
                    timeout=self.timeout,
                    progress_callback=port_progress
                )

                results.append({
                    'host': host_ip,
                    'ports': open_ports
                })

                # 实时发送结果
                if open_ports:
                    result_text = f"[主机] {host_ip}\n"
                    result_text += f"{'='*40}\n"
                    for port_info in open_ports:
                        result_text += f"  端口: {port_info['port']} - 服务: {port_info['service']}\n"
                    self.result_ready.emit(result_text)

            self.log_message.emit("扫描完成", 'info')

        except Exception as e:
            self.log_message.emit(f"扫描出错: {str(e)}", 'error')
            log.error(f"扫描出错: {e}")

        finally:
            self.progress_updated.emit(100, 100, 100)


class MainWindow(QMainWindow, UiMain):
    """主窗口类"""

    def __init__(self):
        super().__init__()
        self.setup_ui(self)
        self.scan_thread = None

    def start_scan(self):
        """开始扫描"""
        host = self.ip_input.text().strip()
        port_range = self.port_input.text().strip()

        if not host:
            QMessageBox.warning(self, '输入错误', '请输入目标IP地址或范围')
            return

        if not port_range:
            QMessageBox.warning(self, '输入错误', '请输入端口范围')
            return

        try:
            timeout = float(self.timeout_input.text() or '1')
            max_workers = int(self.threads_input.text() or '50')
        except ValueError:
            QMessageBox.warning(self, '输入错误', '请输入有效的超时时间和线程数')
            return

        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.ip_input.setEnabled(False)
        self.port_input.setEnabled(False)
        self.progress_bar.setValue(0)
        self.clear_result()

        log.info(f"开始扫描 - 目标: {host}, 端口: {port_range}")
        self.update_log(f"开始扫描 - 目标: {host}, 端口: {port_range}", 'info')

        self.scan_thread = ScanThread(host, port_range, timeout, max_workers)
        self.scan_thread.progress_updated.connect(self.on_progress_updated)
        self.scan_thread.log_message.connect(self.on_log_message)
        self.scan_thread.result_ready.connect(self.on_result_ready)
        self.scan_thread.finished.connect(self.on_scan_finished)
        self.scan_thread.start()

    def stop_scan(self):
        """停止扫描"""
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.scan_thread.wait(3000)
            self.update_log("扫描已停止", 'warning')
            log.warning("扫描被用户停止")

        self.reset_ui()

    def on_progress_updated(self, progress, scanned, total):
        """进度更新回调"""
        self.progress_bar.setValue(progress)

    def on_log_message(self, message, level):
        """日志消息回调"""
        self.update_log(message, level)

    def on_result_ready(self, result_text):
        """结果准备好回调"""
        self.update_result(result_text)

    def on_scan_finished(self):
        """扫描全部完成"""
        self.update_result(f"{'='*40}")
        self.update_result("扫描完成")
        log.info("扫描任务完成")
        self.reset_ui()

    def reset_ui(self):
        """重置UI状态"""
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.ip_input.setEnabled(True)
        self.port_input.setEnabled(True)

    def clear_results(self):
        """清除所有结果"""
        self.clear_result()
        self.clear_log()
        self.progress_bar.setValue(0)


def main():
    """程序入口"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == '__main__':
    main()