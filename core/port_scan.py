"""
端口扫描模块 
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from .logger import log
    from .service_detect import get_service_by_port
except ImportError:
    import logging
    log = logging.getLogger('port_scan')
    from core.service_detect import get_service_by_port


# 端口状态枚举
class PortState:
    OPEN = "open"       # 开放
    CLOSED = "closed"   # 关闭
    FILTERED = "filtered"  # 过滤


# 扫描模式配置 - 5种模式
RECOMMENDED_MODES = {
    'ping': {
        'name': '主机发现',
        'desc': '主机发现（不扫端口）',
        'port_scan': None,
    },
    'fast': {
        'name': '快速扫描',
        'desc': '快速扫描（常用端口）',
        'port_scan': 'tcp-connect',
        'ports': [
            # 文件传输
            20, 21, 22, 23,
            # 邮件
            25, 110, 143, 465, 587, 993, 995,
            # Web
            80, 443, 8080, 8443, 8000, 8888, 5000, 9000,
            # 数据库
            3306, 1433, 1521, 5432, 6379, 27017, 9200,
            # Windows
            135, 137, 138, 139, 445, 3389,
            # 其他
            53, 67, 68, 123, 389, 636, 902, 5900, 1883, 5672, 2222
        ]
    },
    'normal': {
        'name': '标准扫描',
        'desc': '标准扫描（1-10000端口）',
        'port_scan': 'tcp-connect',
        'ports': list(range(1, 10001))
    },
    'syn': {
        'name': 'SYN扫描',
        'desc': 'SYN扫描（1-10000端口）',
        'port_scan': 'tcp-syn',
        'ports': list(range(1, 10001))
    },
    'custom': {
        'name': '指定端口',
        'desc': '自定义端口扫描',
        'port_scan': 'tcp-connect',
        'ports': []
    }
}

# 模式名称到ID的映射
SCAN_MODE_NAMES = {
    '主机发现': 'ping',
    '快速扫描': 'fast',
    '标准扫描': 'normal',
    'SYN扫描': 'syn',
    '指定端口': 'custom'
}


def parse_port_range(port_range):
    """解析端口范围字符串，支持 80,443,1-100 格式"""
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


# 默认线程数
DEFAULT_THREADS = 200

# 默认超时时间
DEFAULT_TIMEOUT = 0.3


def tcp_connect_scan(host, port, timeout=1):
    """TCP Connect 扫描 - 使用socket"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return PortState.OPEN if result == 0 else PortState.CLOSED
    except socket.timeout:
        return PortState.FILTERED
    except ConnectionRefusedError:
        return PortState.CLOSED
    except:
        return PortState.FILTERED


def tcp_syn_scan(host, port, timeout=1):
    """TCP SYN 扫描 - 使用scapy"""
    from scapy.all import IP, TCP, sr1, sr
    try:
        syn_packet = IP(dst=host) / TCP(dport=port, flags='S')
        response = sr1(syn_packet, timeout=timeout, verbose=0)

        if response:
            if int(response.getlayer(TCP).flags) == 0x12:
                rst_packet = IP(dst=host) / TCP(dport=port, flags='R')
                sr(rst_packet, timeout=1, verbose=0)
                return PortState.OPEN
            elif int(response.getlayer(TCP).flags) == 0x14:
                return PortState.CLOSED
        return PortState.FILTERED
    except:
        return PortState.FILTERED


    
def get_scan_function(scan_type):
    """根据扫描类型获取扫描函数"""
    scan_map = {
        'tcp-syn': tcp_syn_scan,
        'tcp-connect': tcp_connect_scan,
        'tcp': tcp_connect_scan
    }
    return scan_map.get(scan_type, tcp_connect_scan)


# SYN扫描线程数（限制避免scapy并发问题）
SYN_MAX_THREADS = 1


def scan_ports(host, ports, progress_callback=None, stop_flag=None, port_found_callback=None,
               scan_type='tcp', timeout=1):
    """
    扫描目标主机的端口

    Args:
        host: 目标主机IP
        ports: 端口列表
        progress_callback: 进度回调
        stop_flag: 停止标志
        port_found_callback: 端口发现回调
        scan_type: 扫描类型 (tcp或tcp-syn)
        timeout: 超时时间
    """
    if not ports:
        return []

    total = len(ports)
    scanned = [0]
    scan_func = get_scan_function(scan_type)

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
            state = scan_func(host, port, timeout=timeout)
            if state == PortState.OPEN:
                return {
                    'port': port,
                    'state': state,
                    'service': get_service_by_port(port)
                }
            return None
        except:
            return None

    # SYN/UDP扫描用小并发（避免scapy多线程问题）
    if scan_type in ['tcp-syn', 'udp']:
        try:
            with ThreadPoolExecutor(max_workers=SYN_MAX_THREADS) as executor:
                futures = {executor.submit(scan_one, port): port for port in ports}
                for future in as_completed(futures):
                    if check_stop():
                        break
                    scanned[0] += 1
                    try:
                        result = future.result()
                        if result and port_found_callback:
                            port_found_callback(host, result['port'], result['service'], result['state'])
                    except:
                        pass
                    if progress_callback:
                        progress = int(scanned[0] / total * 100) if total > 0 else 100
                        progress_callback(progress, scanned[0], total)
        except Exception as e:
            log.error(f"[{host}] 扫描出错: {e}")
    else:
        try:
            with ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
                futures = {executor.submit(scan_one, port): port for port in ports}
                for future in as_completed(futures):
                    if check_stop():
                        break
                    scanned[0] += 1
                    try:
                        result = future.result()
                        if result and port_found_callback:
                            port_found_callback(host, result['port'], result['service'], result['state'])
                    except:
                        pass
                    if progress_callback:
                        progress = int(scanned[0] / total * 100) if total > 0 else 100
                        progress_callback(progress, scanned[0], total)
        except Exception as e:
            log.error(f"[{host}] 扫描出错: {e}")

    return []


if __name__ == '__main__':
    print("=== 扫描模式 ===")
    for mode_id, mode in RECOMMENDED_MODES.items():
        port_count = len(mode.get('ports', [])) if mode.get('ports') else 0
        print(f"{mode_id}. {mode['name']} - {mode['desc']} ({port_count}端口)")