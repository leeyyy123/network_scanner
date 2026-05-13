"""
主机扫描模块 - 负责检测目标主机是否存活
"""

import ipaddress
from scapy.all import IP, TCP, sr1, sr
import ctypes
from ping3 import ping
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from .logger import log
except ImportError:
    import logging
    log = logging.getLogger('host_scan')

# 探测类型枚举
class ProbeType:
    ICMP = "ICMP"
    TCP_SYN = "TCP-SYN"
    TCP_ACK = "TCP-ACK"

# 常用检测端口
CHECK_PORTS = [80, 443, 22, 23, 3389, 445]

# Windows 网络库
WS2_32 = None
try:
    WS2_32 = ctypes.windll.ws2_32
except:
    pass


def is_valid_ip(ip_str):
    """
    验证IP字符串是否合法

    Args:
        ip_str: IP地址字符串

    Returns:
        bool: 是否是合法IP
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def icmp_ping(host, timeout=1):
    """
    ICMP Ping 探测

    Args:
        host: 目标主机IP
        timeout: 超时时间(秒)

    Returns:
        bool: 是否能 Ping 通
    """
    if not is_valid_ip(host):
        log.debug(f"无效IP地址: {host}")
        return False

    try:
        response = ping(host, timeout=timeout)

        if response is not None:
            log.info(f"ICMP Ping 成功: {host} (延迟: {response*1000:.2f}ms)")
            return True
        else:
            log.debug(f"ICMP Ping 超时: {host}")
            return False

    except PermissionError:
        log.debug(f"ICMP Ping 需要管理员权限: {host}")
        return False
    except Exception as e:
        log.debug(f"ICMP Ping 失败: {host} - {e}")
        return False


def tcp_syn_probe(host, port=80, timeout=1):
    """
    TCP SYN 探测 (使用 scapy 发送 SYN 包)

    Args:
        host: 目标主机IP
        port: 端口号
        timeout: 超时时间(秒)

    Returns:
        bool: 是否存活
    """
    if not is_valid_ip(host):
        log.debug(f"无效IP地址: {host}")
        return False

    try:
        syn_packet = IP(dst=host) / TCP(dport=port, flags='S')
        response = sr1(syn_packet, timeout=timeout, verbose=0)

        if response:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                rst_packet = IP(dst=host) / TCP(dport=port, flags='R')
                sr(rst_packet, timeout=1, verbose=0)
                return True
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                return True
        return False
    except Exception as e:
        log.debug(f"TCP SYN 探测失败: {host}:{port} - {e}")
        return False


def tcp_ack_probe(host, port=80, timeout=1):
    """
    TCP ACK 探测 (使用 scapy 发送 ACK 包)

    Args:
        host: 目标主机IP
        port: 端口号
        timeout: 超时时间(秒)

    Returns:
        bool: 是否存活
    """
    if not is_valid_ip(host):
        log.debug(f"无效IP地址: {host}")
        return False

    try:
        ack_packet = IP(dst=host) / TCP(dport=port, flags='A', seq=12345)
        response = sr1(ack_packet, timeout=timeout, verbose=0)

        if response and response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x14:
                return True
        return False
    except Exception as e:
        log.debug(f"TCP ACK 探测失败: {host}:{port} - {e}")
        return False


def is_host_alive(host, timeout=1):
    """
    检测单个主机是否存活 (按优先级顺序探测: ICMP -> TCP-SYN -> TCP-ACK)

    Args:
        host: IP地址字符串
        timeout: 超时时间(秒)

    Returns:
        tuple: (bool, str) - 是否存活, 扫描方式
    """
    # 第一优先级: ICMP Ping
    if icmp_ping(host, timeout):
        return True, ProbeType.ICMP

    # 第二优先级: TCP SYN 探测（减少端口数量提高速度）
    for port in CHECK_PORTS[:2]:  # 只测试前2个端口，避免卡顿
        if tcp_syn_probe(host, port, timeout):
            return True, ProbeType.TCP_SYN

    # 第三优先级: TCP ACK 探测
    for port in CHECK_PORTS[:1]:  # 只测试1个端口
        if tcp_ack_probe(host, port, timeout):
            return True, ProbeType.TCP_ACK

    return False, "None"


def parse_ip_range(ip_range):
    """
    解析IP范围字符串

    支持格式:
    - 单IP: 192.168.1.1
    - IP段: 192.168.1.1-192.168.1.10
    - CIDR: 192.168.1.0/24
    - 多个用逗号分隔
    """
    ips = []
    parts = ip_range.replace(' ', '').split(',')

    for part in parts:
        try:
            # 先尝试 CIDR 或单IP
            net = ipaddress.ip_network(part, strict=False)
            ips.extend([str(ip) for ip in net.hosts()])
        except ValueError:
            # 再尝试 IP 段
            if '-' in part:
                try:
                    start_ip, end_ip = part.split('-')
                    start = ipaddress.ip_address(start_ip)
                    end = ipaddress.ip_address(end_ip)

                    current = int(start)
                    end_int = int(end)
                    while current <= end_int:
                        ips.append(str(ipaddress.ip_address(current)))
                        current += 1
                except:
                    pass
            else:
                # 检查单IP是否合法
                try:
                    ipaddress.ip_address(part)
                    ips.append(part)
                except ValueError:
                    log.warning(f"无效IP地址: {part}")

    return list(set(ips))


def scan_hosts(ip_range, max_workers=50, timeout=1,
               progress_callback=None, stop_flag=None, host_found_callback=None):
    """
    扫描IP范围内的存活主机

    Args:
        ip_range: IP范围字符串
        max_workers: 最大线程数
        timeout: 超时时间(秒)
        progress_callback: 进度回调函数
        stop_flag: 停止标志对象
        host_found_callback: 主机发现回调
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
        return stop_flag is not None and stop_flag.value == 1

    scanned = [0]
    lock = __import__('threading').Lock()

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(is_host_alive, ip, timeout): ip for ip in ips}

            for future in as_completed(futures):
                if check_stop():
                    for f in futures:
                        f.cancel()
                    break

                scanned[0] += 1
                ip = futures[future]
                try:
                    alive, method = future.result()
                    if alive:
                        with lock:
                            alive_hosts.append(ip)
                        if host_found_callback:
                            host_found_callback(ip, method)
                        # 记录到日志文件（包含扫描方式）
                        log.info(f"主机在线: {ip} [{method}]")
                except Exception as e:
                    pass

                if progress_callback:
                    progress = int(scanned[0] / total * 100)
                    progress_callback(progress, scanned[0], total)

    except Exception as e:
        log.error(f"主机扫描出错: {e}")

    log.info(f"主机扫描完成, 发现 {len(alive_hosts)} 个存活主机")
    return alive_hosts


if __name__ == '__main__':
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    # 导入logger（避免相对导入问题）
    from core.logger import log

    print("=== CIDR 测试 ===")
    print(parse_ip_range("192.168.1.0/28"))  # 14个IP

    print("\n=== IP段测试 ===")
    print(parse_ip_range("192.168.1.1-192.168.1.5"))

    print("\n=== 单主机测试 ===")
    print(f"127.0.0.1 是否存活: {is_host_alive('127.0.0.1')}")

    # 测试不存在的 IP
    print(f"\n测试不存在的主机: 192.168.142.7")
    print(f"结果: {is_host_alive('192.168.142.7', timeout=2)}")