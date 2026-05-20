"""
主机扫描模块 - 负责检测目标主机是否存活
"""
import ipaddress
from scapy.all import IP, TCP, sr1, sr
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


def is_valid_ip(ip_str):
    """验证IP字符串是否合法"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def icmp_ping(host, timeout=1):
    """ICMP Ping 探测"""
    if not is_valid_ip(host):
        return False

    try:
        response = ping(host, timeout=timeout)
        if response is not None:
            return True
        return False
    except:
        return False


def tcp_syn_probe(host, port=80, timeout=1):
    """TCP SYN 探测"""
    if not is_valid_ip(host):
        return False

    try:
        syn_packet = IP(dst=host) / TCP(dport=port, flags='S')
        response = sr1(syn_packet, timeout=timeout, verbose=0)

        if response and response.haslayer(TCP):
            flags = int(response.getlayer(TCP).flags)
            if flags == 0x12:
                rst_packet = IP(dst=host) / TCP(dport=port, flags='R')
                sr(rst_packet, timeout=1, verbose=0)
                return True
            elif flags == 0x14:
                return True
        return False
    except:
        return False


def tcp_ack_probe(host, port=80, timeout=1):
    """TCP ACK 探测"""
    if not is_valid_ip(host):
        return False

    try:
        ack_packet = IP(dst=host) / TCP(dport=port, flags='A', seq=12345)
        response = sr1(ack_packet, timeout=timeout, verbose=0)

        if response and response.haslayer(TCP):
            if int(response.getlayer(TCP).flags) == 0x14:
                return True
        return False
    except:
        return False


def is_host_alive(host, timeout=1, methods=None):
    """检测单个主机是否存活"""
    if methods is None:
        methods = ['icmp', 'tcp-syn', 'tcp-ack']

    for method in methods:
        if method == 'icmp' and icmp_ping(host, timeout):
            return True, ProbeType.ICMP
        elif method == 'tcp-syn':
            if tcp_syn_probe(host, CHECK_PORTS[0], timeout):
                return True, ProbeType.TCP_SYN
        elif method == 'tcp-ack':
            if tcp_ack_probe(host, CHECK_PORTS[0], timeout):
                return True, ProbeType.TCP_ACK

    return False, "None"


def parse_ip_range(ip_range):
    """解析IP范围字符串"""
    ips = []
    parts = ip_range.replace(' ', '').split(',')

    for part in parts:
        try:
            net = ipaddress.ip_network(part, strict=False)
            ips.extend([str(ip) for ip in net.hosts()])
        except ValueError:
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
                try:
                    ipaddress.ip_address(part)
                    ips.append(part)
                except ValueError:
                    pass

    return list(set(ips))


def scan_hosts_with_methods(ip_range, methods, max_workers=100, timeout=1,
                            progress_callback=None, stop_flag=None, host_found_callback=None):
    """使用指定探测方法扫描主机"""
    ips = parse_ip_range(ip_range)
    alive_hosts = []
    total = len(ips)

    if total == 0:
        return []

    def check_stop():
        return stop_flag is not None and stop_flag.value == 1

    scanned = [0]
    lock = __import__('threading').Lock()

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(is_host_alive, ip, timeout, methods): ip for ip in ips}

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
                except:
                    pass

                if progress_callback:
                    progress = int(scanned[0] / total * 100)
                    progress_callback(progress, scanned[0], total)

    except Exception as e:
        log.error(f"主机扫描出错: {e}")

    return alive_hosts


if __name__ == '__main__':
    print("=== CIDR 测试 ===")
    print(parse_ip_range("192.168.1.0/28"))

    print("\n=== IP段测试 ===")
    print(parse_ip_range("192.168.1.1-192.168.1.5"))

    print("\n=== 单主机测试 ===")
    print(f"127.0.0.1 是否存活: {is_host_alive('127.0.0.1')}")