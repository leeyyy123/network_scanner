"""
端口扫描模块 - 负责扫描目标主机的开放端口
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from .logger import log
from .service_detect import get_service_by_port


def parse_port_range(port_range):
    """
    解析端口范围字符串

    支持格式:
    - 单端口: 80
    - 端口列表: 80, 443, 22
    - 端口范围: 1-1024
    - 混合: 22, 80, 443, 8000-8100

    Args:
        port_range: 端口范围字符串

    Returns:
        list: 端口号列表
    """
    ports = []
    parts = port_range.replace(' ', '').split(',')

    for part in parts:
        if '-' in part:
            # 端口范围
            try:
                start_port, end_port = part.split('-')
                for port in range(int(start_port), int(end_port) + 1):
                    if 1 <= port <= 65535:
                        ports.append(port)
            except ValueError:
                log.warning(f"无效的端口范围: {part}")
        else:
            # 单个端口
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.append(port)
                else:
                    log.warning(f"端口号超出范围(1-65535): {port}")
            except ValueError:
                log.warning(f"无效的端口号: {part}")

    return sorted(list(set(ports)))  # 去重并排序


def scan_port(host, port, timeout=1):
    """
    扫描单个端口

    Args:
        host: 目标主机IP
        port: 端口号
        timeout: 超时时间(秒)

    Returns:
        dict: {'port': 端口号, 'open': bool, 'service': 服务名}
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        return {
            'port': port,
            'open': result == 0,
            'service': get_service_by_port(port) if result == 0 else None
        }
    except socket.timeout:
        return {'port': port, 'open': False, 'service': None}
    except socket.error as e:
        log.debug(f"扫描端口 {host}:{port} 出错: {e}")
        return {'port': port, 'open': False, 'service': None}


def scan_ports(host, port_range, max_workers=100, timeout=1, progress_callback=None):
    """
    扫描目标主机的端口

    Args:
        host: 目标主机IP
        port_range: 端口范围字符串
        max_workers: 最大线程数
        timeout: 超时时间(秒)
        progress_callback: 进度回调函数 (progress, scanned, total)

    Returns:
        list: 开放端口的信息列表
    """
    log.info(f"开始扫描 {host} 的端口: {port_range}")
    ports = parse_port_range(port_range)
    open_ports = []
    total = len(ports)
    scanned = 0

    if total == 0:
        log.warning(f"未解析到有效端口: {port_range}")
        return []

    log.info(f"共需扫描 {total} 个端口")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, port, timeout): port for port in ports}

        for future in as_completed(futures):
            port = futures[future]
            scanned += 1

            try:
                result = future.result()
                if result['open']:
                    open_ports.append(result)
                    log.info(f"发现开放端口: {host}:{port} [{result['service']}]")
            except Exception as e:
                log.error(f"扫描端口 {host}:{port} 时出错: {e}")

            if progress_callback:
                progress = int(scanned / total * 100)
                progress_callback(progress, scanned, total)

    log.info(f"端口扫描完成, 发现 {len(open_ports)} 个开放端口")
    return open_ports


if __name__ == '__main__':
    # 测试代码
    print(f"解析端口: {parse_port_range('22,80,443,8000-8010')}")

    results = scan_ports('127.0.0.1', '80,443,22', max_workers=10)
    for r in results:
        print(f"端口 {r['port']} 开放 - {r['service']}")