#coding: utf-8
import socket
import os

host = '192.168.1.104'

if os.name == 'nt':
	socket_protocol = socket.IPPROTO_IP
else:
	socket_protocol = socket.IPPROTO_ICMP
	# Linux
	
sniffer = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
# Tcp_Server = socket(AF_INET,SOCK_STREAM)

sniffer.bind((host,0))
# 绑定到所有端口,也就是监听所有端口

sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
# 数据中包含ip头,value为1
# 一种超时机制使其在一定时间后返回而不管是否有数据到来,都会返回
# sniffer = setsocketopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)


if os.name == 'nt':
	sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
	# 在windows平台上,设置ioctl启用混杂模式(需要管理员权限)
	

print sniffer.recvfrom(65565)

if os.name == 'nt':
	sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)
