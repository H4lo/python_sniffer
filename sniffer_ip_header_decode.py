#coding: utf-8

import os
import socket
import struct
from ctypes import *

host = '192.168.1.104'

class IP(Structure):
	_fields_ = [
		('ihl',				c_ubyte,4),		# 头部说明,
		('version',			c_ubyte,4),		# 版本号,
		('tos',				c_ubyte),		# type of server
		('len',				c_ushort),		# ip包总长
		('id',				c_ushort),		# 标识符
		('offset',			c_ushort),		# 偏移(包含了标记和片偏移)
		('ttl',				c_ubyte),		# 生存时间
		('protocol_type',	c_ubyte),		# 协议类型
		('sum',				c_ushort),		# 校验和
		('src',				c_ulong),		# 源ip
		('dst',				c_ulong)		# 目的ip
		
	]
	def __new__(self,socket_buffer=None):
		# self代表类的实例
		# __new__()决定是否要使用该__init__()方法
		return self.from_buffer_copy(socket_buffer)
		# 缓冲区的数据填充到结构体中
		
	def __init__(self,socket_buffer=None):
		# 初始化各个变量
		self.protocol_map = {1:"ICMP",6:"TCP",17:"UDP"}
		self.src_addr = socket.inet_ntoa(struct.pack("<L",self.src))
		self.dst_addr = socket.inet_ntoa(struct.pack("<L",self.dst))
		
		try:
			self.protocol = self.protocol_map[self.protocol_type]
		except:
			self.protocol = str(self.protocol_type)
	
if os.name == 'nt':
	socket_protocol = socket.IPPROTO_IP
else:
	socket_protocol = socket.IPPROTO_ICMP
	# Linux
		
		
sniffer = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
sniffer.bind((host,0))
sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
	
if os.name == 'nt':
	sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
		
try:
	while True:
		raw_buffer = sniffer.recvfrom(65535)[0]
			
		ip_header = IP(raw_buffer[0:20])
		
		print "Protocol: %s %s -> %s"%(ip_header.protocol,ip_header.src_addr,ip_header.dst_addr)

except KeyboardInterrupt:
	if os.name == 'nt':
		sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)
		
		


		
