# -*- coding: utf-8 -*-
# 创建一个临时脚本 list_ifaces.py
from scapy.all import get_if_list, conf

print("可用网卡列表:", get_if_list())
print("当前默认网卡:", conf.iface)