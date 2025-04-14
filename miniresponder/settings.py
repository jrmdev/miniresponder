#!/usr/bin/env python
import os
import sys
import random
import subprocess
import socket

from . import utils

class Settings:

	def __init__(self):
		self.ResponderPATH = os.path.dirname(__file__)
		self.Bind_To = '0.0.0.0'

	def __str__(self):
		ret = 'Settings class:\n'
		for attr in dir(self):
			value = str(getattr(self, attr)).strip()
			if not attr.startswith("__"):
				ret += "    Settings.%s = %s\n" % (attr, value)
		return ret

	def populate(self, options):

		self.Os_version      = sys.platform
		self.PY2OR3          = "PY3"
		self.RespondOnly     = options.RespondOnly

        # Poisoners
		self.LLMNR_On_Off    = True
		self.NBTNS_On_Off    = True
		self.MDNS_On_Off     = True

		# Servers
		self.HTTP_On_Off     = False if self.RespondOnly else True
		self.SSL_On_Off      = False if self.RespondOnly else True
		self.SMB_On_Off      = False if self.RespondOnly else True

		# Generic options
		self.LM_On_Off          = options.LM_On_Off
		self.NOESS_On_Off       = False
		self.Quiet		= options.Quiet
		self.Interface          = options.Interface if options.Interface else utils.FindFirstInterface()
		self.Bind_To            = utils.FindLocalIP(self.Interface)
		self.Bind_To6           = utils.FindLocalIP6(self.Interface)
		self.IPv6               = utils.Probe_IPv6_socket()
		self.IP_aton            = socket.inet_aton(self.Bind_To)
		self.IP_Pton6           = socket.inet_pton(socket.AF_INET6, self.Bind_To6)

		# Generate Random stuff for one Responder session
		self.MachineName       = 'WIN-'+''.join([random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for i in range(11)])
		self.Username          = ''.join([random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(6)])
		self.Domain            = ''.join([random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for i in range(4)])
		self.DHCPHostname      = ''.join([random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for i in range(9)])
		self.DomainName        = self.Domain + '.LOCAL'
		self.MachineNego       = ''.join([random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for i in range(9)]) +'$@'+self.DomainName
		self.RPCPort           = random.randrange(45000, 49999)

		self.NumChal = "random"
		self.Challenge = b''

		# SSL Options
		os.makedirs(os.path.join(self.ResponderPATH, 'certs'), exist_ok=True)
		self.SSLKey  = os.path.join(self.ResponderPATH, 'certs/responder.crt')
		self.SSLCert = os.path.join(self.ResponderPATH, 'certs/responder.key')

		# Generate self-signed certificate if it doesn't exist
		if not os.path.exists(self.SSLKey) or not os.path.exists(self.SSLCert):
			subprocess.run(['openssl', 'genrsa', '-out', self.SSLKey, '2048'])
			subprocess.run(['openssl', 'req', '-new', '-x509', '-days', '3650', '-key', self.SSLKey, '-out', self.SSLCert, '-subj', '/'])

def init():
	global Config
	Config = Settings()
