"""
端口扫描模块 - 负责扫描目标主机的开放端口
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from .logger import log
from .service_detect import get_service_by_port


def parse_port_range(port_range):
    """解析端口范围字符串"""
    ports = []
    parts = port_range.replace(' ', '').split(',')

    for part in parts:
        if '-' in part:
            try:
                start_port, end_port = part.split('-')
                for port in range(int(start_port), int(end_port) + 1):
                    if 1 <= port <= 65535:
                        ports.append(port)
            except ValueError:
                pass
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.append(port)
            except ValueError:
                pass

    return sorted(list(set(ports)))


def scan_ports(host, port_range, max_workers=100, timeout=1,
               progress_callback=None, stop_flag=None, port_found_callback=None):
    """
    扫描目标主机的端口

    Args:
        host: 目标主机IP
        port_range: 端口范围字符串
        max_workers: 最大线程数
        timeout: 超时时间(秒)
        progress_callback: 进度回调 (progress, scanned, total)
        stop_flag: 停止标志对象
        port_found_callback: 端口发现回调 (host, port, service)
    """
    ports = parse_port_range(port_range)
    open_ports = []
    total = len(ports)

    if total == 0:
        return []

    def check_stop():
        if stop_flag is not None:
            try:
                return stop_flag.value == 1
            except:
                return False
        return False

    def scan_one(port):
        if check_stop():
            return None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return {'port': port, 'open': result == 0,
                    'service': get_service_by_port(port) if result == 0 else None}
        except:
            return None

    scanned = [0]
    results_lock = __import__('threading').Lock()

    def handle_result(future):
        if check_stop():
            return
        scanned[0] += 1
        try:
            result = future.result()
            if result and result['open']:
                with results_lock:
                    open_ports.append(result)
                # 立即通知回调
                if port_found_callback:
                    port_found_callback(host, result['port'], result['service'])
        except:
            pass

        if progress_callback:
            progress = int(scanned[0] / total * 100)
            progress_callback(progress, scanned[0], total)

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_one, port): port for port in ports}

            for future in as_completed(futures):
                if check_stop():
                    for f in futures:
                        f.cancel()
                    break
                handle_result(future)

    except Exception as e:
        pass

    return open_ports


if __name__ == '__main__':
    results = scan_ports('127.0.0.1', '80,443,22', max_workers=10)
    for r in results:
        print(f"端口 {r['port']} 开放 - {r['service']}")