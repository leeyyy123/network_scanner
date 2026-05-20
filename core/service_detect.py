"""
服务识别模块 - 负责根据端口号识别网络服务
"""

# 常见端口-服务映射表
PORT_SERVICES = {
    # Web服务
    80: 'HTTP',
    443: 'HTTPS',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt',
    8000: 'HTTP-Alt',
    8888: 'HTTP-Alt',

    # 文件传输
    21: 'FTP',
    20: 'FTP-Data',
    115: 'SFTP',

    # 远程连接
    22: 'SSH',
    23: 'Telnet',
    2222: 'SSH-Alt',

    # 邮件服务
    25: 'SMTP',
    110: 'POP3',
    143: 'IMAP',
    465: 'SMTPS',
    587: 'SMTP-Submit',
    993: 'IMAPS',
    995: 'POP3S',

    # 数据库
    3306: 'MySQL',
    1433: 'MSSQL',
    1521: 'Oracle',
    5432: 'PostgreSQL',
    6379: 'Redis',
    27017: 'MongoDB',
    9200: 'Elasticsearch',

    # 目录服务
    389: 'LDAP',
    636: 'LDAPS',

    # 网络服务
    53: 'DNS',
    67: 'DHCP-Server',
    68: 'DHCP-Client',
    123: 'NTP',

    # 消息队列
    1883: 'MQTT',
    5672: 'AMQP',

    # 虚拟化
    3389: 'RDP',
    5900: 'VNC',

    # 应用服务
    5000: 'Flask-Dev',
    8000: 'Django',
    9000: 'PHP-FPM',

    # 其他常见服务
    135: 'MS-RPC',
    137: 'NetBIOS-NS',
    138: 'NetBIOS-DGM',
    139: 'NetBIOS-SSN',
    445: 'SMB',
    902: 'VMware',
    912: 'VMware-Auth',
    5040: 'SCard-Svr',
    7680: 'MDNS',
    3300: 'MySQL-Cluster',
}


def get_service_by_port(port):
    """
    根据端口号获取服务名称

    Args:
        port: 端口号 (int)

    Returns:
        str: 服务名称，如果未知则返回 'Unknown'
    """
    if isinstance(port, str):
        try:
            port = int(port)
        except ValueError:
            return 'Unknown'

    return PORT_SERVICES.get(port, 'Unknown')


def get_all_services():
    """
    获取所有已知服务的字典

    Returns:
        dict: 端口-服务映射字典
    """
    return PORT_SERVICES.copy()


def is_common_port(port):
    """
    检查是否为常用端口

    Args:
        port: 端口号 (int)

    Returns:
        bool: 是否为常用端口
    """
    return port in PORT_SERVICES