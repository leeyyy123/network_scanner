"""
主机扫描模块 - 负责检测目标主机是否存活
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from .logger import log

# 常用检测端口
CHECK_PORTS = [80, 443, 22, 23, 3389, 445]


def is_host_alive(host, timeout=1):
    """
    检测单个主机是否存活

    Args:
        host: IP地址字符串
        timeout: 超时时间(秒)

    Returns:
        bool: 主机是否存活
    """
    # 先尝试 ICMP ping (需要管理员权限)
    # 如果失败，尝试TCP连接到常用端口
    for port in CHECK_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except (socket.timeout, socket.error, OSError):
            continue

    # 如果所有端口都失败，尝试TCP ping
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, 80))
        sock.close()
        return result == 0
    except:
        return False


def parse_ip_range(ip_range):
    """
    解析IP范围字符串

    支持格式:
    - 单IP: 192.168.1.1
    - IP段: 192.168.1.1-10
    - 多个IP/段用逗号分隔: 192.168.1.1, 192.168.1.10-20

    Args:
        ip_range: IP范围字符串

    Returns:
        list: IP地址列表
    """
    ips = []
    parts = ip_range.replace(' ', '').split(',')

    for part in parts:
        if '-' in part:
            # IP段
            try:
                start_ip, end_ip = part.split('-')
                start_parts = start_ip.split('.')
                end_parts = end_ip.split('.')

                if len(start_parts) != 4 or len(end_parts) != 4:
                    log.warning(f"无效的IP段格式: {part}")
                    continue

                # 获取前三个部分作为基础
                base = '.'.join(start_parts[:3])
                start_last = int(start_parts[3])
                end_last = int(end_parts[3])

                for i in range(start_last, end_last + 1):
                    ips.append(f"{base}.{i}")
            except (ValueError, IndexError) as e:
                log.warning(f"解析IP段失败: {part}, 错误: {e}")
        else:
            # 单个IP
            ips.append(part)

    return ips


def scan_hosts(ip_range, max_workers=50, timeout=1, progress_callback=None):
    """
    扫描IP范围内的存活主机

    Args:
        ip_range: IP范围字符串
        max_workers: 最大线程数
        timeout: 超时时间(秒)
        progress_callback: 进度回调函数

    Returns:
        list: 存活主机的IP地址列表
    """
    log.info(f"开始扫描主机: {ip_range}")
    ips = parse_ip_range(ip_range)
    alive_hosts = []
    total = len(ips)
    scanned = 0

    if total == 0:
        log.warning(f"未解析到有效IP地址: {ip_range}")
        return []

    log.info(f"共需扫描 {total} 个IP地址")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(is_host_alive, ip, timeout): ip for ip in ips}

        for future in as_completed(futures):
            ip = futures[future]
            scanned += 1

            try:
                if future.result():
                    alive_hosts.append(ip)
                    log.info(f"主机在线: {ip}")
            except Exception as e:
                log.error(f"扫描主机 {ip} 时出错: {e}")

            if progress_callback:
                progress = int(scanned / total * 100)
                progress_callback(progress, scanned, total)

    log.info(f"主机扫描完成, 发现 {len(alive_hosts)} 个存活主机")
    return alive_hosts


if __name__ == '__main__':
    # 测试代码
    test_ips = "192.168.1.1-10"
    print(f"解析测试: {parse_ip_range(test_ips)}")

    hosts = scan_hosts("127.0.0.1", max_workers=10)
    print(f"存活主机: {hosts}")