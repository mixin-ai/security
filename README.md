1.按照依赖
python3 -m pip install scapy

2.允许程序
sudo python3 arpSpoofing.py 被攻击对象IP 网关IP
```
sudo python3 arpSpoofing.py 192.168.1.153 192.168.1.1
```
2.1 被攻击对象IP
  可以使用arp -a 获取局域网内的ip列表，可以一个个尝试
2.2 网关IP
  路由器的ip （一般为192.168.1.1)
  netstat -rn | grep default
  
