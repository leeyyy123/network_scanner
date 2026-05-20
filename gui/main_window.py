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
from core.host_scan import scan_hosts_with_methods, parse_ip_range
from core.port_scan import scan_ports, RECOMMENDED_MODES, SCAN_MODE_NAMES, parse_port_range


class StopFlag:
    """停止标志类"""
    def __init__(self):
        self.value = 0

    def stop(self):
        self.value = 1

    def reset(self):
        self.value = 0


class ScanThread(QThread):
    """扫描线程 - 在后台执行扫描任务"""

    progress_updated = pyqtSignal(int, int, int)
    log_message = pyqtSignal(str, str)
    host_found = pyqtSignal(str, str)  # host, method
    port_found = pyqtSignal(str, int, str, str)  # host, port, service, state
    scan_complete = pyqtSignal()

    def __init__(self, host, mode_id, custom_ports=None):
        super().__init__()
        self.host = host
        self.mode_id = mode_id
        self.custom_ports = custom_ports or []
        self.scan_mode = RECOMMENDED_MODES.get(mode_id, RECOMMENDED_MODES['fast'])
        self.stop_flag = StopFlag()

    def stop(self):
        """请求停止扫描"""
        self.stop_flag.stop()
        self.log_message.emit("[停止] 已停止扫描", 'warning')

    def run(self):
        """执行扫描"""
        try:
            # 阶段1: 主机发现
            if self.scan_mode.get('port_scan') is None:
                # ping模式: 仅主机发现，不扫描端口
                self.log_message.emit(f"开始主机发现: {self.host}", 'info')

                def host_progress(progress, scanned, total):
                    self.progress_updated.emit(progress, scanned, total)

                def host_found_callback(ip, method):
                    self.host_found.emit(ip, method)

                alive_hosts = scan_hosts_with_methods(
                    self.host,
                    ['icmp', 'tcp-syn', 'tcp-ack'],
                    max_workers=100,
                    timeout=1,
                    progress_callback=host_progress,
                    stop_flag=self.stop_flag,
                    host_found_callback=host_found_callback
                )

                if self.stop_flag.value == 1:
                    self.log_message.emit("[停止] 主机发现已停止", 'warning')
                    self.scan_complete.emit()
                    return

                if alive_hosts:
                    self.log_message.emit(f"发现 {len(alive_hosts)} 个存活主机", 'info')
                else:
                    self.log_message.emit("未发现存活主机", 'warning')

                self.scan_complete.emit()
                return

            # 其他模式: 先主机发现，再端口扫描
            self.log_message.emit(f"开始主机发现: {self.host}", 'info')

            def host_progress(progress, scanned, total):
                self.progress_updated.emit(int(progress / 2), scanned, total)

            def host_found_callback(ip, method):
                self.host_found.emit(ip, method)

            alive_hosts = scan_hosts_with_methods(
                self.host,
                ['icmp', 'tcp-syn', 'tcp-ack'],
                max_workers=100,
                timeout=1,
                progress_callback=host_progress,
                stop_flag=self.stop_flag,
                host_found_callback=host_found_callback
            )

            if self.stop_flag.value == 1:
                self.log_message.emit("[停止] 主机发现已停止", 'warning')
                self.scan_complete.emit()
                return

            if not alive_hosts:
                self.log_message.emit("未发现存活主机", 'warning')
                self.scan_complete.emit()
                return

            self.log_message.emit(f"发现 {len(alive_hosts)} 个存活主机", 'info')

            # 阶段2: 端口扫描
            # 指定端口模式使用custom_ports，其他模式使用预设ports
            if self.custom_ports:
                port_list = self.custom_ports
            else:
                port_list = self.scan_mode.get('ports', [])

            scan_type = self.scan_mode.get('port_scan', 'tcp-syn')
            self.log_message.emit(f"端口数量: {len(port_list)}, 类型: {scan_type}", 'info')

            for idx, host_ip in enumerate(alive_hosts):
                if self.stop_flag.value == 1:
                    self.log_message.emit("[停止] 端口扫描已停止", 'warning')
                    break

                self.log_message.emit(f"正在扫描主机: {host_ip}", 'info')

                def port_progress(progress, scanned, total):
                    self.progress_updated.emit(
                        int(50 + 50 / len(alive_hosts) * (idx + progress / 100)),
                        scanned,
                        total
                    )

                # 端口发现时实时通知
                def port_found_callback(h, p, s, state):
                    self.port_found.emit(h, p, s, state)

                scan_ports(
                    host_ip,
                    port_list,
                    progress_callback=port_progress,
                    stop_flag=self.stop_flag,
                    port_found_callback=port_found_callback,
                    scan_type=scan_type
                )

                if self.stop_flag.value == 1:
                    break

            if self.stop_flag.value == 0:
                self.log_message.emit("扫描完成", 'info')

        except Exception as e:
            self.log_message.emit(f"扫描出错: {str(e)}", 'error')
            log.error(f"扫描出错: {e}")

        finally:
            self.progress_updated.emit(100, 100, 100)
            self.scan_complete.emit()


class MainWindow(QMainWindow, UiMain):
    """主窗口类"""

    def __init__(self):
        super().__init__()
        self.setup_ui(self)
        self.scan_thread = None
        self.scan_results = []
        self.current_mode_id = None
        self._displayed = False

        # 模式切换时显示/隐藏端口输入框
        self.scan_mode_combo.currentTextChanged.connect(self.on_mode_changed)

    def on_mode_changed(self, mode_name):
        """模式切换时调用"""
        mode_id = SCAN_MODE_NAMES.get(mode_name, 'fast')
        if mode_id == 'custom':
            self.port_label.setVisible(True)
            self.port_input.setVisible(True)
        else:
            self.port_label.setVisible(False)
            self.port_input.setVisible(False)

    def start_scan(self):
        """开始扫描"""
        host = self.ip_input.text().strip()

        if not host:
            QMessageBox.warning(self, '输入错误', '请输入目标IP地址或范围')
            return

        # 验证IP格式
        ips = parse_ip_range(host)
        if not ips:
            QMessageBox.warning(self, '输入错误', '无效的IP地址或范围')
            return

        # 获取扫描模式
        mode_name = self.scan_mode_combo.currentText()
        mode_id = SCAN_MODE_NAMES.get(mode_name, 'fast')

        # 指定端口模式需要验证端口输入
        custom_ports = []
        if mode_id == 'custom':
            port_str = self.port_input.text().strip()
            if not port_str:
                QMessageBox.warning(self, '输入错误', '请输入端口范围')
                return
            custom_ports = parse_port_range(port_str)
            if not custom_ports:
                QMessageBox.warning(self, '输入错误', '无效的端口范围')
                return

        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.ip_input.setEnabled(False)
        self.scan_mode_combo.setEnabled(False)
        self.progress_bar.setValue(0)
        self.clear_result()

        self.current_mode_id = mode_id
        self.scan_results = []
        self._displayed = False

        mode_info = RECOMMENDED_MODES[mode_id]
        port_desc = f"{len(custom_ports)}个端口" if mode_id == 'custom' else mode_info['desc']
        self.update_log(f"扫描模式: {port_desc}", 'info')

        self.scan_thread = ScanThread(host, mode_id, custom_ports)
        self.scan_thread.progress_updated.connect(self.on_progress_updated)
        self.scan_thread.log_message.connect(self.on_log_message)
        self.scan_thread.host_found.connect(self.on_host_found)
        self.scan_thread.port_found.connect(self.on_port_found)
        self.scan_thread.scan_complete.connect(self.on_scan_complete)
        self.scan_thread.start()

    def stop_scan(self):
        """停止扫描"""
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            log.warning("扫描被用户停止")

    def on_progress_updated(self, progress, scanned, total):
        """进度更新回调"""
        self.progress_bar.setValue(progress)

    def on_log_message(self, message, level):
        """日志消息回调"""
        self.update_log(message, level)

    def on_host_found(self, host, method='ICMP'):
        """发现存活主机"""
        self.update_log(f"[+] 发现存活主机: {host}", 'info')
        if host not in [r['host'] for r in self.scan_results]:
            self.scan_results.append({'host': host, 'ports': []})

    def on_port_found(self, host, port, service, state):
        """发现端口 - 只处理开放状态的端口"""
        if state != 'open':
            return  # 忽略被过滤的端口
        state_display = {
            'open': '开放',
            'closed': '关闭',
            'filtered': '被过滤',
            'open|filtered': '开放或过滤'
        }
        state_text = state_display.get(state, state)
        self.update_log(f"[+] {host}:{port} [{service}] - {state_text}", 'info')
        for result in self.scan_results:
            if result['host'] == host:
                result['ports'].append({'port': port, 'service': service, 'state': state})
                break

    def on_scan_complete(self):
        """扫描完成回调"""
        if not self._displayed:
            self._displayed = True
            self.display_results()
        self.reset_ui()

    def display_results(self):
        """显示扫描结果"""
        self.update_result("=" * 50)
        self.update_result("扫描结果汇总")
        self.update_result("=" * 50)

        if not self.scan_results:
            self.update_result("\n未发现存活主机或开放端口")
            return

        state_display = {
            'open': 'open',
            'closed': 'closed',
            'filtered': 'filtered',
            'open|filtered': 'open|filtered'
        }

        for result in self.scan_results:
            self.update_result(f"\n[主机] {result['host']}")
            self.update_result("-" * 40)
            # 仅端口扫描模式才显示"未发现开放端口"
            if result['ports']:
                for port_info in result['ports']:
                    state = state_display.get(port_info.get('state', 'open'), 'open')
                    self.update_result(f"  {port_info['port']}/{state} - {port_info['service']}")
            elif self.current_mode_id != 'ping':
                self.update_result("  未发现开放端口")

        self.update_result("")
        if self.scan_thread and self.scan_thread.stop_flag.value == 1:
            self.update_result("[已停止] 扫描被用户中断")
        else:
            self.update_result("[完成] 扫描已完成")

    def reset_ui(self):
        """重置UI状态"""
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.ip_input.setEnabled(True)
        self.scan_mode_combo.setEnabled(True)

    def clear_results(self):
        """清除所有结果"""
        self.clear_result()
        self.clear_log()
        self.progress_bar.setValue(0)
        self.scan_results = []
        self._displayed = False


def main():
    """程序入口"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == '__main__':
    main()