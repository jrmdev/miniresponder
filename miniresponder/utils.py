#!/usr/bin/env python
import os
import sys
import re
import logging
import socket
import datetime
import codecs
import struct
import random

from random import getrandbits
from calendar import timegm
from . import settings

def if_nametoindex2(name):
	return socket.if_nametoindex(settings.Config.Interface)

def RandomChallenge():
	if settings.Config.NumChal == "random":
		NumChal = b'%016x' % getrandbits(16 * 4)
		Challenge = b''
		for i in range(0, len(NumChal),2):
			Challenge += NumChal[i:i+2]
		return codecs.decode(Challenge, 'hex')
	else:
		return settings.Config.Challenge

def HTTPCurrentDate():
	Date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
	return Date

def SMBTime():
   dt = datetime.datetime.now()
   dt = dt.replace(tzinfo=None)
   return struct.pack("<Q",116444736000000000 + (timegm(dt.timetuple()) * 10000000)).decode('latin-1')

def color(txt, code = 1, modifier = 0):
	return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def text(txt):
	stripcolors = re.sub(r'\x1b\[([0-9,A-Z]{1,2}(;[0-9]{1,2})?(;[0-9]{3})?)?[m|K]?', '', txt)
	logging.info(stripcolors)
	if os.name == 'nt':
		return txt
	return '\r' + re.sub(r'\[([^]]*)\]', "\033[1;34m[\\1]\033[0m", txt)

def PrintHash(Info):
	if 'fullhash' in Info:
		print(Info['fullhash'])

def IsOnTheSameSubnet(ip, net):
	net += '/24'
	ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
	netstr, bits = net.split('/')
	netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
	mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
	return (ipaddr & mask) == (netaddr & mask)

def RespondWithIPAton():
	return settings.Config.IP_aton.decode('latin-1')

def RespondWithIPPton():
	return settings.Config.IP_Pton6.decode('latin-1')

def RespondWithIP():
	return settings.Config.Bind_To

def RespondWithIP6():
	return settings.Config.Bind_To6

def IsIPv6IP(IP):
	if IP == None:
		return False
	regex = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
	ret  = re.search(regex, IP)
	if ret:
		return True
	else:
		return False

def FindFirstInterface():
	ifaces = socket.if_nameindex()
	for iface in ifaces:
		if iface[1] != 'lo':
			return iface[1]
	print("[!] Error: Network interface not found, please specify one with -I option")
	sys.exit(-1)

def FindLocalIP(Iface):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.setsockopt(socket.SOL_SOCKET, 25, str(Iface+'\0').encode('utf-8'))
		s.connect(("127.0.0.1",9))#RFC 863
		ret = s.getsockname()[0]
		s.close()
		return ret
			
	except socket.error:
		print("[!] Error: %s: Interface4 not found" % Iface)
		sys.exit(-1)

def Probe_IPv6_socket():
	"""Return true is IPv6 sockets are really supported, and False when IPv6 is not supported."""
	if not socket.has_ipv6:
		return False
	try:
		with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
			s.bind(("::1", 0))
		return True
	except:
		return False
		
def FindLocalIP6(Iface):
	with open('/proc/net/if_inet6', 'r') as f:
		for line in f:
			parts = line.strip().split()
			if parts[5] == Iface:
				addr = parts[0]
				ipv6 = ':'.join(addr[i:i+4] for i in range(0, 32, 4))
				return ipv6
	raise ValueError(f"No IPv6 address found for {Iface}")
		
def Struct(endian,data):
	return struct.pack(endian, len(data)).decode('latin-1')

def StructWithLen(endian,data):
	return struct.pack(endian, data).decode('latin-1')

def SendBuffer(data):
	return bytes(str(data), 'latin-1')

def RecvBuffer(data):
	return str(data.decode('latin-1'))
	
def Parse_IPV6_Addr(data):
	if data[len(data)-4:len(data)] == b'\x00\x1c\x00\x01':
		return 'IPv6'
	elif data[len(data)-4:len(data)] == b'\x00\x01\x00\x01':
		return True
	elif data[len(data)-4:len(data)] == b'\x00\xff\x00\x01':
		return True
	return False

def IsIPv6(data):
	return False if "::ffff:" in data else True
	
def Decode_Name(nbname):  #From http://code.google.com/p/dpkt/ with author's permission.
	try:
		from string import printable

		if len(nbname) != 32:
			return nbname
		
		l = []
		for i in range(0, 32, 2):
			l.append(chr(((ord(nbname[i]) - 0x41) << 4) | ((ord(nbname[i+1]) - 0x41) & 0xf)))
		
		return ''.join(list(filter(lambda x: x in printable, ''.join(l).split('\x00', 1)[0].replace(' ', ''))))
	except:
		return "Illegal NetBIOS name"


def NBT_NS_Role(data):
	return {
		"\x41\x41\x00":"Workstation/Redirector",
		"\x42\x4c\x00":"Domain Master Browser",
		"\x42\x4d\x00":"Domain Controller",
		"\x42\x4e\x00":"Local Master Browser",
		"\x42\x4f\x00":"Browser Election",
		"\x43\x41\x00":"File Server",
		"\x41\x42\x00":"Browser",
	}.get(data, 'Service not known')


