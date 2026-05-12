"""
主机扫描模块 - 负责检测目标主机是否存活
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from .logger import log

# 常用检测端口
CHECK_PORTS = [80, 443, 22, 23, 3389, 445]


def is_host_alive(host, timeout=1):
    """检测单个主机是否存活"""
    for port in CHECK_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except:
            continue
    return False


def parse_ip_range(ip_range):
    """解析IP范围字符串"""
    ips = []
    parts = ip_range.replace(' ', '').split(',')

    for part in parts:
        if '-' in part:
            try:
                start_ip, end_ip = part.split('-')
                start_parts = start_ip.split('.')
                end_parts = end_ip.split('.')

                if len(start_parts) != 4 or len(end_parts) != 4:
                    continue

                base = '.'.join(start_parts[:3])
                start_last = int(start_parts[3])
                end_last = int(end_parts[3])

                for i in range(start_last, end_last + 1):
                    ips.append(f"{base}.{i}")
            except:
                continue
        else:
            ips.append(part)

    return ips


def scan_hosts(ip_range, max_workers=50, timeout=1,
               progress_callback=None, stop_flag=None, host_found_callback=None):
    """
    扫描IP范围内的存活主机

    Args:
        ip_range: IP范围字符串
        max_workers: 最大线程数
        timeout: 超时时间(秒)
        progress_callback: 进度回调函数 (progress, scanned, total)
        stop_flag: 停止标志对象
        host_found_callback: 主机发现回调 (ip)
    """
    log.info(f"开始扫描主机: {ip_range}")
    ips = parse_ip_range(ip_range)
    alive_hosts = []
    total = len(ips)

    if total == 0:
        log.warning(f"未解析到有效IP地址: {ip_range}")
        return []

    log.info(f"共需扫描 {total} 个IP地址")

    def check_stop():
        if stop_flag is not None:
            try:
                return stop_flag.value == 1
            except:
                return False
        return False

    scanned = [0]
    results_lock = __import__('threading').Lock()

    def check_host(ip):
        if check_stop():
            return False
        return is_host_alive(ip, timeout)

    def handle_result(future):
        if check_stop():
            return
        scanned[0] += 1
        ip = futures[future]
        try:
            if future.result():
                with results_lock:
                    alive_hosts.append(ip)
                # 立即通知回调
                if host_found_callback:
                    host_found_callback(ip)
                log.info(f"主机在线: {ip}")
        except:
            pass

        if progress_callback:
            progress = int(scanned[0] / total * 100)
            progress_callback(progress, scanned[0], total)

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_host, ip): ip for ip in ips}

            for future in as_completed(futures):
                if check_stop():
                    for f in futures:
                        f.cancel()
                    break
                handle_result(future)

    except Exception as e:
        log.error(f"主机扫描出错: {e}")

    log.info(f"主机扫描完成, 发现 {len(alive_hosts)} 个存活主机")
    return alive_hosts