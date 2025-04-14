#!/usr/bin/env python
import struct
import codecs
import random
import re
from . import settings
from os import urandom
from base64 import b64decode, b64encode
from collections import OrderedDict
from .utils import HTTPCurrentDate, SMBTime, RespondWithIPAton, RespondWithIPPton, RespondWithIP, Struct, RecvBuffer, StructWithLen

# Packet class handling all packet generation (see odict.py).
class Packet():
	fields = OrderedDict([
		("data", ""),
	])
	def __init__(self, **kw):
		self.fields = OrderedDict(self.__class__.fields)
		for k,v in kw.items():
			if callable(v):
				self.fields[k] = v(self.fields[k])
			else:
				self.fields[k] = v
	def __str__(self):
		return "".join(map(str, self.fields.values()))

# NBT Answer Packet
class NBT_Ans(Packet):
	fields = OrderedDict([
		("Tid",           ""),
		("Flags",         "\x85\x00"),
		("Question",      "\x00\x00"),
		("AnswerRRS",     "\x00\x01"),
		("AuthorityRRS",  "\x00\x00"),
		("AdditionalRRS", "\x00\x00"),
		("NbtName",       ""),
		("Type",          "\x00\x20"),
		("Classy",        "\x00\x01"),
		("TTL",           "\x00\x04\x93\xe0"), #TTL: 3 days, 11 hours, 20 minutes (Default windows behavior)
		("Len",           "\x00\x06"),
		("Flags1",        "\x00\x00"),
		("IP",            "\x00\x00\x00\x00"),
	])

	def calculate(self,data):
		self.fields["Tid"] = RecvBuffer(data[0:2])
		self.fields["NbtName"] = RecvBuffer(data[12:46])
		self.fields["IP"] = RespondWithIPAton()

# LLMNR Answer Packet
class LLMNR_Ans(Packet):
	fields = OrderedDict([
		("Tid",              ""),
		("Flags",            "\x80\x00"),
		("Question",         "\x00\x01"),
		("AnswerRRS",        "\x00\x01"),
		("AuthorityRRS",     "\x00\x00"),
		("AdditionalRRS",    "\x00\x00"),
		("QuestionNameLen",  "\x09"),
		("QuestionName",     ""),
		("QuestionNameNull", "\x00"),
		("Type",             "\x00\x01"),
		("Class",            "\x00\x01"),
		("AnswerNameLen",    "\x09"),
		("AnswerName",       ""),
		("AnswerNameNull",   "\x00"),
		("Type1",            "\x00\x01"),
		("Class1",           "\x00\x01"),
		("TTL",              "\x00\x00\x00\x1e"),##Poison for 30 sec (Default windows behavior)
		("IPLen",            "\x00\x04"),
		("IP",               "\x00\x00\x00\x00"),
	])

	def calculate(self):
		self.fields["IP"] = RespondWithIPAton()
		self.fields["IPLen"] = Struct(">h",self.fields["IP"])
		self.fields["AnswerNameLen"] = Struct(">B",self.fields["AnswerName"])
		self.fields["QuestionNameLen"] = Struct(">B",self.fields["QuestionName"])

class LLMNR6_Ans(Packet):
	fields = OrderedDict([
		("Tid",              ""),
		("Flags",            "\x80\x00"),
		("Question",         "\x00\x01"),
		("AnswerRRS",        "\x00\x01"),
		("AuthorityRRS",     "\x00\x00"),
		("AdditionalRRS",    "\x00\x00"),
		("QuestionNameLen",  "\x09"),
		("QuestionName",     ""),
		("QuestionNameNull", "\x00"),
		("Type",             "\x00\x1c"),
		("Class",            "\x00\x01"),
		("AnswerNameLen",    "\x09"),
		("AnswerName",       ""),
		("AnswerNameNull",   "\x00"),
		("Type1",            "\x00\x1c"),
		("Class1",           "\x00\x01"),
		("TTL",              "\x00\x00\x00\x1e"),##Poison for 30 sec (Default windows behavior).
		("IPLen",            "\x00\x04"),
		("IP",               "\x00\x00\x00\x00"),
	])

	def calculate(self):
		self.fields["IP"] = RespondWithIPPton()
		self.fields["IPLen"] = Struct(">h",self.fields["IP"])
		self.fields["AnswerNameLen"] = Struct(">B",self.fields["AnswerName"])
		self.fields["QuestionNameLen"] = Struct(">B",self.fields["QuestionName"])
		
# MDNS Answer Packet
class MDNS_Ans(Packet):
	fields = OrderedDict([
		("Tid",              "\x00\x00"),
		("Flags",            "\x84\x00"),
		("Question",         "\x00\x00"),
		("AnswerRRS",        "\x00\x01"),
		("AuthorityRRS",     "\x00\x00"),
		("AdditionalRRS",    "\x00\x00"),
		("AnswerName",       ""),
		("AnswerNameNull",   "\x00"),
		("Type",             "\x00\x01"),
		("Class",            "\x00\x01"),
		("TTL",              "\x00\x00\x00\x78"),##Poison for 2mn (Default windows behavior)
		("IPLen",            "\x00\x04"),
		("IP",               "\x00\x00\x00\x00"),
	])

	def calculate(self):
		self.fields["IP"] = RespondWithIPAton()
		self.fields["IPLen"] = Struct(">h",self.fields["IP"])

# MDNS6 Answer Packet
class MDNS6_Ans(Packet):
	fields = OrderedDict([
		("Tid",              "\x00\x00"),
		("Flags",            "\x84\x00"),
		("Question",         "\x00\x00"),
		("AnswerRRS",        "\x00\x01"),
		("AuthorityRRS",     "\x00\x00"),
		("AdditionalRRS",    "\x00\x00"),
		("AnswerName",       ""),
		("AnswerNameNull",   "\x00"),
		("Type",             "\x00\x1c"),
		("Class",            "\x00\x01"),
		("TTL",              "\x00\x00\x00\x78"),##Poison for 2mn (Default windows behavior)
		("IPLen",            "\x00\x04"),
		("IP",               "\x00\x00\x00\x00"),
	])

	def calculate(self):
		self.fields["IP"] = RespondWithIPPton()
		self.fields["IPLen"] = Struct(">h",self.fields["IP"])

##### HTTP Packets #####
class NTLM_Challenge(Packet):
	fields = OrderedDict([
		("Signature",        "NTLMSSP"),
		("SignatureNull",    "\x00"),
		("MessageType",      "\x02\x00\x00\x00"),
		("TargetNameLen",    "\x06\x00"),
		("TargetNameMaxLen", "\x06\x00"),
		("TargetNameOffset", "\x38\x00\x00\x00"),
		("NegoFlags",        "\x05\x02\x81\xa2" if settings.Config.NOESS_On_Off else "\x05\x02\x89\xa2"),
		("ServerChallenge",  ""),
		("Reserved",         "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("TargetInfoLen",    "\x7e\x00"),
		("TargetInfoMaxLen", "\x7e\x00"),
		("TargetInfoOffset", "\x3e\x00\x00\x00"),
		("NTLMOsVersion",    "\x0a\x00\x7c\x4f\x00\x00\x00\x0f"),
		("TargetNameStr",    settings.Config.Domain),
		("Av1",              "\x02\x00"),#nbt name
		("Av1Len",           "\x06\x00"),
		("Av1Str",           settings.Config.Domain),
		("Av2",              "\x01\x00"),#Server name
		("Av2Len",           "\x14\x00"),
		("Av2Str",           settings.Config.MachineName),
		("Av3",              "\x04\x00"),#Full Domain name
		("Av3Len",           "\x12\x00"),
		("Av3Str",           settings.Config.DomainName),
		("Av4",              "\x03\x00"),#Full machine domain name
		("Av4Len",           "\x28\x00"),
		("Av4Str",           settings.Config.MachineName+'.'+settings.Config.DomainName),
		("Av5",              "\x05\x00"),#Domain Forest Name
		("Av5Len",           "\x12\x00"),
		("Av5Str",           settings.Config.DomainName),
		("Av6",              "\x00\x00"),#AvPairs Terminator
		("Av6Len",           "\x00\x00"),
	])

	def calculate(self):
		# First convert to unicode
		self.fields["TargetNameStr"] = self.fields["TargetNameStr"].encode('utf-16le')
		self.fields["Av1Str"] = self.fields["Av1Str"].encode('utf-16le')
		self.fields["Av2Str"] = self.fields["Av2Str"].encode('utf-16le')
		self.fields["Av3Str"] = self.fields["Av3Str"].encode('utf-16le')
		self.fields["Av4Str"] = self.fields["Av4Str"].encode('utf-16le')
		self.fields["Av5Str"] = self.fields["Av5Str"].encode('utf-16le')
		#Now from bytes to str..
		self.fields["TargetNameStr"] = self.fields["TargetNameStr"].decode('latin-1')
		self.fields["Av1Str"] = self.fields["Av1Str"].decode('latin-1')
		self.fields["Av2Str"] = self.fields["Av2Str"].decode('latin-1')
		self.fields["Av3Str"] = self.fields["Av3Str"].decode('latin-1')
		self.fields["Av4Str"] = self.fields["Av4Str"].decode('latin-1')
		self.fields["Av5Str"] = self.fields["Av5Str"].decode('latin-1')
		# Then calculate

		CalculateNameOffset = str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str("A"*8)+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])

		CalculateAvPairsOffset = CalculateNameOffset+str(self.fields["TargetNameStr"])
		CalculateAvPairsLen = str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])

		# Target Name Offsets
		self.fields["TargetNameOffset"] = Struct("<i",CalculateNameOffset)
		self.fields["TargetNameLen"] = Struct("<h",self.fields["TargetNameStr"])
		self.fields["TargetNameMaxLen"] = Struct("<h",self.fields["TargetNameStr"])
		# AvPairs Offsets
		self.fields["TargetInfoOffset"] = Struct("<i",CalculateAvPairsOffset)
		self.fields["TargetInfoLen"] = Struct("<h",CalculateAvPairsLen)
		self.fields["TargetInfoMaxLen"] = Struct("<h",CalculateAvPairsLen)
		# AvPairs StrLen
		self.fields["Av1Len"] = Struct("<h",self.fields["Av1Str"])
		self.fields["Av2Len"] = Struct("<h",self.fields["Av2Str"])
		self.fields["Av3Len"] = Struct("<h",self.fields["Av3Str"])
		self.fields["Av4Len"] = Struct("<h",self.fields["Av4Str"])
		self.fields["Av5Len"] = Struct("<h",self.fields["Av5Str"])

class IIS_Auth_401_Ans(Packet):
	fields = OrderedDict([
		("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
		("Type",          "Content-Type: text/html\r\n"),
		("ServerType",    "Server: Microsoft-IIS/10.0\r\n"),
		("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
		("WWW-Auth",      "WWW-Authenticate: Negotiate\r\n"),
		("WWW-Auth2",     "WWW-Authenticate: NTLM\r\n"),
		("Len",           "Content-Length: "),
		("ActualLen",     "76"),
		("CRLF",          "\r\n\r\n"),
		("Payload",       """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
<title>401 - Unauthorized: Access is denied due to invalid credentials.</title>
<style type="text/css">
<!--
body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}
fieldset{padding:0 15px 10px 15px;} 
h1{font-size:2.4em;margin:0;color:#FFF;}
h2{font-size:1.7em;margin:0;color:#CC0000;} 
h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;} 
#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:"trebuchet MS", Verdana, sans-serif;color:#FFF;
background-color:#555555;}
#content{margin:0 0 0 2%;position:relative;}
.content-container{background:#FFF;width:96%;margin-top:8px;padding:10px;position:relative;}
-->
</style>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
 <div class="content-container"><fieldset>
  <h2>401 - Unauthorized: Access is denied due to invalid credentials.</h2>
  <h3>You do not have permission to view this directory or page using the credentials that you supplied.</h3>
 </fieldset></div>
</div>
</body>
</html>
"""),
	])
	def calculate(self):
		self.fields["ActualLen"] = len(str(self.fields["Payload"]))

class IIS_Auth_Granted(Packet):
	fields = OrderedDict([
		("Code",          "HTTP/1.1 200 OK\r\n"),
		("ServerType",    "Server: Microsoft-IIS/10.0\r\n"),
		("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
		("Type",          "Content-Type: text/html\r\n"),
		("WWW-Auth",      "WWW-Authenticate: NTLM\r\n"),
		("ContentLen",    "Content-Length: "),
		("ActualLen",     "76"),
		("CRLF",          "\r\n\r\n"),
		("Payload",       ""),
	])
	def calculate(self):
		self.fields["ActualLen"] = len(str(self.fields["Payload"]))

class IIS_NTLM_Challenge_Ans(Packet):
	fields = OrderedDict([
		("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
		("ServerType",    "Server: Microsoft-IIS/10.0\r\n"),
		("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
		("Type",          "Content-Type: text/html\r\n"),
		("WWWAuth",       "WWW-Authenticate: NTLM "),
		("Payload",       ""),
		("Payload-CRLF",  "\r\n"),
		("ContentLen",    "Content-Length: "),
		("ActualLen",     "76"),
		("CRLF",          "\r\n\r\n"),
		("Payload2",       """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>Not Authorized</TITLE>
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>
<BODY><h2>Not Authorized</h2>
<hr><p>HTTP Error 401. The requested resource requires user authentication.</p>
</BODY></HTML>
"""),
	])
	def calculate(self):
		self.fields["ActualLen"] = len(str(self.fields["Payload2"]))

class IIS_Basic_401_Ans(Packet):
	fields = OrderedDict([
		("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
		("ServerType",    "Server: Microsoft-IIS/10.0\r\n"),
		("Type",          "Content-Type: text/html\r\n"),
		("WWW-Auth",      "WWW-Authenticate: Basic realm=\"Authentication Required\"\r\n"),
		("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
		("Len",           "Content-Length: "),
		("ActualLen",     "76"),
		("CRLF",          "\r\n\r\n"),
		("Payload",       """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
<title>401 - Unauthorized: Access is denied due to invalid credentials.</title>
<style type="text/css">
<!--
body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}
fieldset{padding:0 15px 10px 15px;} 
h1{font-size:2.4em;margin:0;color:#FFF;}
h2{font-size:1.7em;margin:0;color:#CC0000;} 
h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;} 
#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:"trebuchet MS", Verdana, sans-serif;color:#FFF;
background-color:#555555;}
#content{margin:0 0 0 2%;position:relative;}
.content-container{background:#FFF;width:96%;margin-top:8px;padding:10px;position:relative;}
-->
</style>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
 <div class="content-container"><fieldset>
  <h2>401 - Unauthorized: Access is denied due to invalid credentials.</h2>
  <h3>You do not have permission to view this directory or page using the credentials that you supplied.</h3>
 </fieldset></div>
</div>
</body>
</html>
"""),
	])
	def calculate(self):
		self.fields["ActualLen"] = len(str(self.fields["Payload"]))

##### Proxy mode Packets #####
class WPADScript(Packet):
	fields = OrderedDict([
		("Code",          "HTTP/1.1 200 OK\r\n"),
		("Type",          "Content-Type: application/x-ns-proxy-autoconfig\r\n"),
		("Cache",         "Pragma: no-cache\r\n"),
		("Server",        "Server: BigIP\r\n"),
		("ContentLen",    "Content-Length: "),
		("ActualLen",     "76"),
		("CRLF",          "\r\n\r\n"),
		("Payload",       "function FindProxyForURL(url, host){return 'PROXY "+RespondWithIP()+":3141; DIRECT';}"),
	])
	def calculate(self):
		self.fields["ActualLen"] = len(str(self.fields["Payload"]))

##### SMB Packets #####
class SMBHeader(Packet):
	fields = OrderedDict([
		("proto", "\xff\x53\x4d\x42"),
		("cmd", "\x72"),
		("errorcode", "\x00\x00\x00\x00"),
		("flag1", "\x00"),
		("flag2", "\x00\x00"),
		("pidhigh", "\x00\x00"),
		("signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("reserved", "\x00\x00"),
		("tid", "\x00\x00"),
		("pid", "\x00\x00"),
		("uid", "\x00\x00"),
		("mid", "\x00\x00"),
	])

class SMBNego(Packet):
	fields = OrderedDict([
		("wordcount", "\x00"),
		("bcc", "\x62\x00"),
		("data", "")
	])

	def calculate(self):
		self.fields["bcc"] = Struct("<h",self.fields["data"])

class SMBNegoAnsLM(Packet):
	fields = OrderedDict([
		("Wordcount",    "\x11"),
		("Dialect",      ""),
		("Securitymode", "\x03"),
		("MaxMpx",       "\x32\x00"),
		("MaxVc",        "\x01\x00"),
		("Maxbuffsize",  "\x04\x41\x00\x00"),
		("Maxrawbuff",   "\x00\x00\x01\x00"),
		("Sessionkey",   "\x00\x00\x00\x00"),
		("Capabilities", "\xfc\x3e\x01\x00"),
		("Systemtime",   SMBTime()),
		("Srvtimezone",  "\x2c\x01"),
		("Keylength",    "\x08"),
		("Bcc",          "\x10\x00"),
		("Key",          ""),
		("Domain",       settings.Config.Domain),
		("DomainNull",   "\x00\x00"),
		("Server",       settings.Config.MachineName),
		("ServerNull",   "\x00\x00"),
	])

	def calculate(self):
		self.fields["Domain"] = self.fields["Domain"].encode('utf-16le').decode('latin-1')
		self.fields["Server"] = self.fields["Server"].encode('utf-16le').decode('latin-1')
		CompleteBCCLen =  str(self.fields["Key"])+str(self.fields["Domain"])+str(self.fields["DomainNull"])+str(self.fields["Server"])+str(self.fields["ServerNull"])
		self.fields["Bcc"] = StructWithLen("<h",len(CompleteBCCLen))
		self.fields["Keylength"] = StructWithLen("<h",len(self.fields["Key"]))[0]

class SMBNegoAns(Packet):
	fields = OrderedDict([
		("Wordcount",    "\x11"),
		("Dialect",      ""),
		("Securitymode", "\x03"),
		("MaxMpx",       "\x32\x00"),
		("MaxVc",        "\x01\x00"),
		("MaxBuffSize",  "\x04\x41\x00\x00"),
		("MaxRawBuff",   "\x00\x00\x01\x00"),
		("SessionKey",   "\x00\x00\x00\x00"),
		("Capabilities", "\xfd\xf3\x01\x80"),
		("SystemTime",   SMBTime()),
		("SrvTimeZone",  "\xf0\x00"),
		("KeyLen",    "\x00"),
		("Bcc",          "\x57\x00"),
		("Guid",         urandom(16).decode('latin-1')),
		("InitContextTokenASNId",     "\x60"),
		("InitContextTokenASNLen",    "\x5b"),
		("ThisMechASNId",             "\x06"),
		("ThisMechASNLen",            "\x06"),
		("ThisMechASNStr",            "\x2b\x06\x01\x05\x05\x02"),
		("SpNegoTokenASNId",          "\xA0"),
		("SpNegoTokenASNLen",         "\x51"),
		("NegTokenASNId",             "\x30"),
		("NegTokenASNLen",            "\x4f"),
		("NegTokenTag0ASNId",         "\xA0"),
		("NegTokenTag0ASNLen",        "\x30"),
		("NegThisMechASNId",          "\x30"),
		("NegThisMechASNLen",         "\x2e"),
		("NegThisMech4ASNId",         "\x06"),
		("NegThisMech4ASNLen",        "\x09"),
		("NegThisMech4ASNStr",        "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
		("NegTokenTag3ASNId",         "\xA3"),
		("NegTokenTag3ASNLen",        "\x1b"),
		("NegHintASNId",              "\x30"),
		("NegHintASNLen",             "\x19"),
		("NegHintTag0ASNId",          "\xa0"),
		("NegHintTag0ASNLen",         "\x17"),
		("NegHintFinalASNId",         "\x1b"),
		("NegHintFinalASNLen",        "\x15"),
		("NegHintFinalASNStr",        "not_defined_in_RFC4178@please_ignore"),
	])

	def calculate(self):
		CompleteBCCLen1 =  str(self.fields["Guid"])+str(self.fields["InitContextTokenASNId"])+str(self.fields["InitContextTokenASNLen"])+str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
		AsnLenStart = str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
		AsnLen2 = str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
		MechTypeLen = str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])
		Tag3Len = str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])

		self.fields["Bcc"] = StructWithLen("<h",len(CompleteBCCLen1))
		self.fields["InitContextTokenASNLen"] = StructWithLen("<B", len(AsnLenStart))
		self.fields["ThisMechASNLen"] = StructWithLen("<B", len(str(self.fields["ThisMechASNStr"])))
		self.fields["SpNegoTokenASNLen"] = StructWithLen("<B", len(AsnLen2))
		self.fields["NegTokenASNLen"] = StructWithLen("<B", len(AsnLen2)-2)
		self.fields["NegTokenTag0ASNLen"] = StructWithLen("<B", len(MechTypeLen))
		self.fields["NegThisMechASNLen"] = StructWithLen("<B", len(MechTypeLen)-2)
		self.fields["NegThisMech4ASNLen"] = StructWithLen("<B", len(str(self.fields["NegThisMech4ASNStr"])))
		self.fields["NegTokenTag3ASNLen"] = StructWithLen("<B", len(Tag3Len))
		self.fields["NegHintASNLen"] = StructWithLen("<B", len(Tag3Len)-2)
		self.fields["NegHintTag0ASNLen"] = StructWithLen("<B", len(Tag3Len)-4)
		self.fields["NegHintFinalASNLen"] = StructWithLen("<B", len(str(self.fields["NegHintFinalASNStr"])))

class SMBNegoKerbAns(Packet):
	fields = OrderedDict([
		("Wordcount",                "\x11"),
		("Dialect",                  ""),
		("Securitymode",             "\x03"),
		("MaxMpx",                   "\x32\x00"),
		("MaxVc",                    "\x01\x00"),
		("MaxBuffSize",              "\x04\x41\x00\x00"),
		("MaxRawBuff",               "\x00\x00\x01\x00"),
		("SessionKey",               "\x00\x00\x00\x00"),
		("Capabilities",             "\xfd\xf3\x01\x80"),
		("SystemTime",               "\x84\xd6\xfb\xa3\x01\x35\xcd\x01"),
		("SrvTimeZone",               "\xf0\x00"),
		("KeyLen",                    "\x00"),
		("Bcc",                       "\x57\x00"),
		("Guid",                      urandom(16).decode('latin-1')),
		("InitContextTokenASNId",     "\x60"),
		("InitContextTokenASNLen",    "\x5b"),
		("ThisMechASNId",             "\x06"),
		("ThisMechASNLen",            "\x06"),
		("ThisMechASNStr",            "\x2b\x06\x01\x05\x05\x02"),
		("SpNegoTokenASNId",          "\xA0"),
		("SpNegoTokenASNLen",         "\x51"),
		("NegTokenASNId",             "\x30"),
		("NegTokenASNLen",            "\x4f"),
		("NegTokenTag0ASNId",         "\xA0"),
		("NegTokenTag0ASNLen",        "\x30"),
		("NegThisMechASNId",          "\x30"),
		("NegThisMechASNLen",         "\x2e"),
		("NegThisMech1ASNId",         "\x06"),
		("NegThisMech1ASNLen",        "\x09"),
		("NegThisMech1ASNStr",        "\x2a\x86\x48\x82\xf7\x12\x01\x02\x02"),
		("NegThisMech2ASNId",         "\x06"),
		("NegThisMech2ASNLen",        "\x09"),
		("NegThisMech2ASNStr",        "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"),
		("NegThisMech3ASNId",         "\x06"),
		("NegThisMech3ASNLen",        "\x0a"),
		("NegThisMech3ASNStr",        "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x03"),
		("NegThisMech4ASNId",         "\x06"),
		("NegThisMech4ASNLen",        "\x09"),
		("NegThisMech4ASNStr",        "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
		("NegTokenTag3ASNId",         "\xA3"),
		("NegTokenTag3ASNLen",        "\x1b"),
		("NegHintASNId",              "\x30"),
		("NegHintASNLen",             "\x19"),
		("NegHintTag0ASNId",          "\xa0"),
		("NegHintTag0ASNLen",         "\x17"),
		("NegHintFinalASNId",         "\x1b"),
		("NegHintFinalASNLen",        "\x15"),
		("NegHintFinalASNStr",        settings.Config.MachineNego),
	])

	def calculate(self):
		CompleteBCCLen1 =  str(self.fields["Guid"])+str(self.fields["InitContextTokenASNId"])+str(self.fields["InitContextTokenASNLen"])+str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech1ASNId"])+str(self.fields["NegThisMech1ASNLen"])+str(self.fields["NegThisMech1ASNStr"])+str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
		AsnLenStart = str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech1ASNId"])+str(self.fields["NegThisMech1ASNLen"])+str(self.fields["NegThisMech1ASNStr"])+str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
		AsnLen2 = str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech1ASNId"])+str(self.fields["NegThisMech1ASNLen"])+str(self.fields["NegThisMech1ASNStr"])+str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
		MechTypeLen = str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech1ASNId"])+str(self.fields["NegThisMech1ASNLen"])+str(self.fields["NegThisMech1ASNStr"])+str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])
		Tag3Len = str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])

		self.fields["Bcc"] = StructWithLen("<h",len(CompleteBCCLen1))
		self.fields["InitContextTokenASNLen"] = StructWithLen("<B", len(AsnLenStart))
		self.fields["ThisMechASNLen"] = StructWithLen("<B", len(str(self.fields["ThisMechASNStr"])))
		self.fields["SpNegoTokenASNLen"] = StructWithLen("<B", len(AsnLen2))
		self.fields["NegTokenASNLen"] = StructWithLen("<B", len(AsnLen2)-2)
		self.fields["NegTokenTag0ASNLen"] = StructWithLen("<B", len(MechTypeLen))
		self.fields["NegThisMechASNLen"] = StructWithLen("<B", len(MechTypeLen)-2)
		self.fields["NegThisMech1ASNLen"] = StructWithLen("<B", len(str(self.fields["NegThisMech1ASNStr"])))
		self.fields["NegThisMech2ASNLen"] = StructWithLen("<B", len(str(self.fields["NegThisMech2ASNStr"])))
		self.fields["NegThisMech3ASNLen"] = StructWithLen("<B", len(str(self.fields["NegThisMech3ASNStr"])))
		self.fields["NegThisMech4ASNLen"] = StructWithLen("<B", len(str(self.fields["NegThisMech4ASNStr"])))
		self.fields["NegTokenTag3ASNLen"] = StructWithLen("<B", len(Tag3Len))
		self.fields["NegHintASNLen"] = StructWithLen("<B", len(Tag3Len)-2)
		self.fields["NegHintFinalASNLen"] = StructWithLen("<B", len(str(self.fields["NegHintFinalASNStr"])))

class SMBSession1Data(Packet):
	fields = OrderedDict([
		("Wordcount",             "\x04"),
		("AndXCommand",           "\xff"),
		("Reserved",              "\x00"),
		("Andxoffset",            "\x5f\x01"),
		("Action",                "\x00\x00"),
		("SecBlobLen",            "\xea\x00"),
		("Bcc",                   "\x34\x01"),
		("ChoiceTagASNId",        "\xa1"),
		("ChoiceTagASNLenOfLen",  "\x81"),
		("ChoiceTagASNIdLen",     "\x00"),
		("NegTokenTagASNId",      "\x30"),
		("NegTokenTagASNLenOfLen","\x81"),
		("NegTokenTagASNIdLen",   "\x00"),
		("Tag0ASNId",             "\xA0"),
		("Tag0ASNIdLen",          "\x03"),
		("NegoStateASNId",        "\x0A"),
		("NegoStateASNLen",       "\x01"),
		("NegoStateASNValue",     "\x01"),
		("Tag1ASNId",             "\xA1"),
		("Tag1ASNIdLen",          "\x0c"),
		("Tag1ASNId2",            "\x06"),
		("Tag1ASNId2Len",         "\x0A"),
		("Tag1ASNId2Str",         "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
		("Tag2ASNId",             "\xA2"),
		("Tag2ASNIdLenOfLen",     "\x81"),
		("Tag2ASNIdLen",          "\xED"),
		("Tag3ASNId",             "\x04"),
		("Tag3ASNIdLenOfLen",     "\x81"),
		("Tag3ASNIdLen",          "\xEA"),
		("NTLMSSPSignature",      "NTLMSSP"),
		("NTLMSSPSignatureNull",  "\x00"),
		("NTLMSSPMessageType",    "\x02\x00\x00\x00"),
		("NTLMSSPNtWorkstationLen","\x1e\x00"),
		("NTLMSSPNtWorkstationMaxLen","\x1e\x00"),
		("NTLMSSPNtWorkstationBuffOffset","\x38\x00\x00\x00"),
		("NTLMSSPNtNegotiateFlags","\x15\x82\x81\xe2" if settings.Config.NOESS_On_Off else "\x15\x82\x89\xe2"),
		("NTLMSSPNtServerChallenge","\x81\x22\x33\x34\x55\x46\xe7\x88"),
		("NTLMSSPNtReserved","\x00\x00\x00\x00\x00\x00\x00\x00"),
		("NTLMSSPNtTargetInfoLen","\x94\x00"),
		("NTLMSSPNtTargetInfoMaxLen","\x94\x00"),
		("NTLMSSPNtTargetInfoBuffOffset","\x56\x00\x00\x00"),
		("NegTokenInitSeqMechMessageVersionHigh","\x05"),
		("NegTokenInitSeqMechMessageVersionLow","\x02"),
		("NegTokenInitSeqMechMessageVersionBuilt","\xce\x0e"),
		("NegTokenInitSeqMechMessageVersionReserved","\x00\x00\x00"),
		("NegTokenInitSeqMechMessageVersionNTLMType","\x0f"),
		("NTLMSSPNtWorkstationName",settings.Config.Domain),
		("NTLMSSPNTLMChallengeAVPairsId","\x02\x00"),
		("NTLMSSPNTLMChallengeAVPairsLen","\x0a\x00"),
		("NTLMSSPNTLMChallengeAVPairsUnicodeStr",settings.Config.Domain),
		("NTLMSSPNTLMChallengeAVPairs1Id","\x01\x00"),
		("NTLMSSPNTLMChallengeAVPairs1Len","\x1e\x00"),
		("NTLMSSPNTLMChallengeAVPairs1UnicodeStr",settings.Config.MachineName),
		("NTLMSSPNTLMChallengeAVPairs2Id","\x04\x00"),
		("NTLMSSPNTLMChallengeAVPairs2Len","\x1e\x00"),
		("NTLMSSPNTLMChallengeAVPairs2UnicodeStr",settings.Config.MachineName+'.'+settings.Config.DomainName),
		("NTLMSSPNTLMChallengeAVPairs3Id","\x03\x00"),
		("NTLMSSPNTLMChallengeAVPairs3Len","\x1e\x00"),
		("NTLMSSPNTLMChallengeAVPairs3UnicodeStr",settings.Config.DomainName),
		("NTLMSSPNTLMChallengeAVPairs5Id","\x05\x00"),
		("NTLMSSPNTLMChallengeAVPairs5Len","\x04\x00"),
		("NTLMSSPNTLMChallengeAVPairs5UnicodeStr",settings.Config.DomainName),
		("NTLMSSPNTLMChallengeAVPairs6Id","\x00\x00"),
		("NTLMSSPNTLMChallengeAVPairs6Len","\x00\x00"),
		("NTLMSSPNTLMPadding",             ""),
		("NativeOs","Windows Server 2003 3790 Service Pack 2"),
		("NativeOsTerminator","\x00\x00"),
		("NativeLAN", "Windows Server 2003 5.2"),
		("NativeLANTerminator","\x00\x00"),
	])

	def calculate(self):
		###### Convert strings to Unicode
		self.fields["NTLMSSPNtWorkstationName"] = self.fields["NTLMSSPNtWorkstationName"].encode('utf-16le').decode('latin-1')
		self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"].encode('utf-16le').decode('latin-1')
		self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"].encode('utf-16le').decode('latin-1')
		self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"].encode('utf-16le').decode('latin-1')
		self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"].encode('utf-16le').decode('latin-1')
		self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"].encode('utf-16le').decode('latin-1')
		self.fields["NativeOs"] = self.fields["NativeOs"].encode('utf-16le').decode('latin-1')
		self.fields["NativeLAN"] = self.fields["NativeLAN"].encode('utf-16le').decode('latin-1')

		###### SecBlobLen Calc:
		AsnLen = str(self.fields["ChoiceTagASNId"])+str(self.fields["ChoiceTagASNLenOfLen"])+str(self.fields["ChoiceTagASNIdLen"])+str(self.fields["NegTokenTagASNId"])+str(self.fields["NegTokenTagASNLenOfLen"])+str(self.fields["NegTokenTagASNIdLen"])+str(self.fields["Tag0ASNId"])+str(self.fields["Tag0ASNIdLen"])+str(self.fields["NegoStateASNId"])+str(self.fields["NegoStateASNLen"])+str(self.fields["NegoStateASNValue"])+str(self.fields["Tag1ASNId"])+str(self.fields["Tag1ASNIdLen"])+str(self.fields["Tag1ASNId2"])+str(self.fields["Tag1ASNId2Len"])+str(self.fields["Tag1ASNId2Str"])+str(self.fields["Tag2ASNId"])+str(self.fields["Tag2ASNIdLenOfLen"])+str(self.fields["Tag2ASNIdLen"])+str(self.fields["Tag3ASNId"])+str(self.fields["Tag3ASNIdLenOfLen"])+str(self.fields["Tag3ASNIdLen"])
		CalculateSecBlob = str(self.fields["NTLMSSPSignature"])+str(self.fields["NTLMSSPSignatureNull"])+str(self.fields["NTLMSSPMessageType"])+str(self.fields["NTLMSSPNtWorkstationLen"])+str(self.fields["NTLMSSPNtWorkstationMaxLen"])+str(self.fields["NTLMSSPNtWorkstationBuffOffset"])+str(self.fields["NTLMSSPNtNegotiateFlags"])+str(self.fields["NTLMSSPNtServerChallenge"])+str(self.fields["NTLMSSPNtReserved"])+str(self.fields["NTLMSSPNtTargetInfoLen"])+str(self.fields["NTLMSSPNtTargetInfoMaxLen"])+str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])+str(self.fields["NTLMSSPNtWorkstationName"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])

		###### Bcc len
		BccLen = AsnLen+CalculateSecBlob+str(self.fields["NTLMSSPNTLMPadding"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsTerminator"])+str(self.fields["NativeLAN"])+str(self.fields["NativeLANTerminator"])

		###### SecBlobLen
		self.fields["SecBlobLen"] = StructWithLen("<h", len(AsnLen+CalculateSecBlob))
		self.fields["Bcc"] = StructWithLen("<h", len(BccLen))
		self.fields["ChoiceTagASNIdLen"] = StructWithLen(">B", len(AsnLen+CalculateSecBlob)-3)
		self.fields["NegTokenTagASNIdLen"] = StructWithLen(">B", len(AsnLen+CalculateSecBlob)-6)
		self.fields["Tag1ASNIdLen"] = StructWithLen(">B", len(str(self.fields["Tag1ASNId2"])+str(self.fields["Tag1ASNId2Len"])+str(self.fields["Tag1ASNId2Str"])))
		self.fields["Tag1ASNId2Len"] = StructWithLen(">B", len(str(self.fields["Tag1ASNId2Str"])))
		self.fields["Tag2ASNIdLen"] = StructWithLen(">B", len(CalculateSecBlob+str(self.fields["Tag3ASNId"])+str(self.fields["Tag3ASNIdLenOfLen"])+str(self.fields["Tag3ASNIdLen"])))
		self.fields["Tag3ASNIdLen"] = StructWithLen(">B", len(CalculateSecBlob))

		###### Andxoffset calculation.
		CalculateCompletePacket = str(self.fields["Wordcount"])+str(self.fields["AndXCommand"])+str(self.fields["Reserved"])+str(self.fields["Andxoffset"])+str(self.fields["Action"])+str(self.fields["SecBlobLen"])+str(self.fields["Bcc"])+BccLen
		self.fields["Andxoffset"] = StructWithLen("<h", len(CalculateCompletePacket)+32)

		###### Workstation Offset
		CalculateOffsetWorkstation = str(self.fields["NTLMSSPSignature"])+str(self.fields["NTLMSSPSignatureNull"])+str(self.fields["NTLMSSPMessageType"])+str(self.fields["NTLMSSPNtWorkstationLen"])+str(self.fields["NTLMSSPNtWorkstationMaxLen"])+str(self.fields["NTLMSSPNtWorkstationBuffOffset"])+str(self.fields["NTLMSSPNtNegotiateFlags"])+str(self.fields["NTLMSSPNtServerChallenge"])+str(self.fields["NTLMSSPNtReserved"])+str(self.fields["NTLMSSPNtTargetInfoLen"])+str(self.fields["NTLMSSPNtTargetInfoMaxLen"])+str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])

		###### AvPairs Offset
		CalculateLenAvpairs = str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])

		##### Workstation Offset Calculation:
		self.fields["NTLMSSPNtWorkstationBuffOffset"] = StructWithLen("<i", len(CalculateOffsetWorkstation))
		self.fields["NTLMSSPNtWorkstationLen"] = StructWithLen("<h", len(str(self.fields["NTLMSSPNtWorkstationName"])))
		self.fields["NTLMSSPNtWorkstationMaxLen"] = StructWithLen("<h", len(str(self.fields["NTLMSSPNtWorkstationName"])))

		##### IvPairs Offset Calculation:
		self.fields["NTLMSSPNtTargetInfoBuffOffset"] = StructWithLen("<i", len(CalculateOffsetWorkstation+str(self.fields["NTLMSSPNtWorkstationName"])))
		self.fields["NTLMSSPNtTargetInfoLen"] = StructWithLen("<h", len(CalculateLenAvpairs))
		self.fields["NTLMSSPNtTargetInfoMaxLen"] = StructWithLen("<h", len(CalculateLenAvpairs))

		##### IvPair Calculation:
		self.fields["NTLMSSPNTLMChallengeAVPairs5Len"] = StructWithLen("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])))
		self.fields["NTLMSSPNTLMChallengeAVPairs3Len"] = StructWithLen("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])))
		self.fields["NTLMSSPNTLMChallengeAVPairs2Len"] = StructWithLen("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])))
		self.fields["NTLMSSPNTLMChallengeAVPairs1Len"] = StructWithLen("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])))
		self.fields["NTLMSSPNTLMChallengeAVPairsLen"] = StructWithLen("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])))

class SMBSession2Accept(Packet):
	fields = OrderedDict([
		("Wordcount",             "\x04"),
		("AndXCommand",           "\xff"),
		("Reserved",              "\x00"),
		("Andxoffset",            "\xb4\x00"),
		("Action",                "\x00\x00"),
		("SecBlobLen",            "\x09\x00"),
		("Bcc",                   "\x89\x01"),
		("SSPIAccept","\xa1\x07\x30\x05\xa0\x03\x0a\x01\x00"),
		("NativeOs","Windows Server 2003 3790 Service Pack 2"),
		("NativeOsTerminator","\x00\x00"),
		("NativeLAN", "Windows Server 2003 5.2"),
		("NativeLANTerminator","\x00\x00"),
	])
	def calculate(self):
		self.fields["NativeOs"] = self.fields["NativeOs"].encode('utf-16le')
		self.fields["NativeLAN"] = self.fields["NativeLAN"].encode('utf-16le')
		BccLen = str(self.fields["SSPIAccept"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsTerminator"])+str(self.fields["NativeLAN"])+str(self.fields["NativeLANTerminator"])
		self.fields["Bcc"] = StructWithLen("<h", len(BccLen))

class SMBSessEmpty(Packet):
	fields = OrderedDict([
		("Empty",       "\x00\x00\x00"),
	])

class SMBTreeData(Packet):
	fields = OrderedDict([
		("Wordcount", "\x07"),
		("AndXCommand", "\xff"),
		("Reserved","\x00" ),
		("Andxoffset", "\xbd\x00"),
		("OptionalSupport","\x00\x00"),
		("MaxShareAccessRight","\x00\x00\x00\x00"),
		("GuestShareAccessRight","\x00\x00\x00\x00"),
		("Bcc", "\x94\x00"),
		("Service", "IPC"),
		("ServiceTerminator","\x00\x00\x00\x00"),
	])

	def calculate(self):
		## Complete Packet Len
		CompletePacket= str(self.fields["Wordcount"])+str(self.fields["AndXCommand"])+str(self.fields["Reserved"])+str(self.fields["Andxoffset"])+str(self.fields["OptionalSupport"])+str(self.fields["MaxShareAccessRight"])+str(self.fields["GuestShareAccessRight"])+str(self.fields["Bcc"])+str(self.fields["Service"])+str(self.fields["ServiceTerminator"])
		## AndXOffset
		self.fields["Andxoffset"] = StructWithLen("<H", len(CompletePacket)+32)
		## BCC Len Calc
		BccLen= str(self.fields["Service"])+str(self.fields["ServiceTerminator"])
		self.fields["Bcc"] = StructWithLen("<H", len(BccLen))

### SMB2 Packets
class SMB2Header(Packet):
    fields = OrderedDict([
        ("Proto",         "\xfe\x53\x4d\x42"),
        ("Len",           "\x40\x00"),#Always 64.
        ("CreditCharge",  "\x00\x00"),
        ("NTStatus",      "\x00\x00\x00\x00"),
        ("Cmd",           "\x00\x00"),
        ("Credits",       "\x01\x00"),
        ("Flags",         "\x01\x00\x00\x00"),
        ("NextCmd",       "\x00\x00\x00\x00"),
        ("MessageId",     "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("PID",           "\x00\x00\x00\x00"),
        ("TID",           "\x00\x00\x00\x00"),
        ("SessionID",     "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("Signature",     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    ])

class SMB2NegoAns(Packet):
	fields = OrderedDict([
		("Len",             "\x41\x00"),
		("Signing",         "\x01\x00"),
		("Dialect",         "\xff\x02"),
		("Reserved",        "\x00\x00"),
		("Guid",            urandom(16).decode('latin-1')),
		("Capabilities",    "\x07\x00\x00\x00"),
		("MaxTransSize",    "\x00\x00\x10\x00"),
		("MaxReadSize",     "\x00\x00\x10\x00"),
		("MaxWriteSize",    "\x00\x00\x10\x00"),
		("SystemTime",      SMBTime()),
		("BootTime",        SMBTime()),
		("SecBlobOffSet",             "\x80\x00"),
		("SecBlobLen",                "\x78\x00"),
		("Reserved2",                 "\x00\x00\x00\x00"),
		("InitContextTokenASNId",     "\x60"),
		("InitContextTokenASNLen",    "\x76"),
		("ThisMechASNId",             "\x06"),
		("ThisMechASNLen",            "\x06"),
		("ThisMechASNStr",            "\x2b\x06\x01\x05\x05\x02"),
		("SpNegoTokenASNId",          "\xA0"),
		("SpNegoTokenASNLen",         "\x6c"),
		("NegTokenASNId",             "\x30"),
		("NegTokenASNLen",            "\x6a"),
		("NegTokenTag0ASNId",         "\xA0"),
		("NegTokenTag0ASNLen",        "\x3c"),
		("NegThisMechASNId",          "\x30"),
		("NegThisMechASNLen",         "\x3a"),
		#("NegThisMech1ASNId",         "\x06"),
		#("NegThisMech1ASNLen",        "\x0a"),
		#("NegThisMech1ASNStr",        "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x1e"),
		("NegThisMech2ASNId",         "\x06"),
		("NegThisMech2ASNLen",        "\x09"),
		("NegThisMech2ASNStr",        "\x2a\x86\x48\x82\xf7\x12\x01\x02\x02"),
		("NegThisMech3ASNId",         "\x06"),
		("NegThisMech3ASNLen",        "\x09"),
		("NegThisMech3ASNStr",        "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"),
		("NegThisMech4ASNId",         "\x06"),
		("NegThisMech4ASNLen",        "\x0a"),
		("NegThisMech4ASNStr",        "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x03"),
		("NegThisMech5ASNId",         "\x06"),
		("NegThisMech5ASNLen",        "\x0a"),
		("NegThisMech5ASNStr",        "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
		("NegTokenTag3ASNId",         "\xA3"),
		("NegTokenTag3ASNLen",        "\x2a"),
		("NegHintASNId",              "\x30"),
		("NegHintASNLen",             "\x28"),
		("NegHintTag0ASNId",          "\xa0"),
		("NegHintTag0ASNLen",         "\x26"),
		("NegHintFinalASNId",         "\x1b"), 
		("NegHintFinalASNLen",        "\x24"),
		("NegHintFinalASNStr",        "not_defined_in_RFC4178@please_ignore"),
	])

	def calculate(self):
		StructLen = str(self.fields["Len"])+str(self.fields["Signing"])+str(self.fields["Dialect"])+str(self.fields["Reserved"])+str(self.fields["Guid"])+str(self.fields["Capabilities"])+str(self.fields["MaxTransSize"])+str(self.fields["MaxReadSize"])+str(self.fields["MaxWriteSize"])+str(self.fields["SystemTime"])+str(self.fields["BootTime"])+str(self.fields["SecBlobOffSet"])+str(self.fields["SecBlobLen"])+str(self.fields["Reserved2"])
		SecBlobLen = str(self.fields["InitContextTokenASNId"])+str(self.fields["InitContextTokenASNLen"])+str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegThisMech5ASNId"])+str(self.fields["NegThisMech5ASNLen"])+str(self.fields["NegThisMech5ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
		AsnLenStart = str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegThisMech5ASNId"])+str(self.fields["NegThisMech5ASNLen"])+str(self.fields["NegThisMech5ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
		AsnLen2 = str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegThisMech5ASNId"])+str(self.fields["NegThisMech5ASNLen"])+str(self.fields["NegThisMech5ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
		MechTypeLen = str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegThisMech5ASNId"])+str(self.fields["NegThisMech5ASNLen"])+str(self.fields["NegThisMech5ASNStr"])
		Tag3Len = str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
        #Packet Struct len
		self.fields["Len"] = StructWithLen("<h",len(StructLen)+1)
        #Sec Blob lens
		self.fields["SecBlobOffSet"] = StructWithLen("<h",len(StructLen)+64)
		self.fields["SecBlobLen"] = StructWithLen("<h",len(SecBlobLen))
        #ASN Stuff
		self.fields["InitContextTokenASNLen"] = StructWithLen("<B", len(SecBlobLen)-2)
		self.fields["ThisMechASNLen"] = StructWithLen("<B", len(str(self.fields["ThisMechASNStr"])))
		self.fields["SpNegoTokenASNLen"] = StructWithLen("<B", len(AsnLen2))
		self.fields["NegTokenASNLen"] = StructWithLen("<B", len(AsnLen2)-2)
		self.fields["NegTokenTag0ASNLen"] = StructWithLen("<B", len(MechTypeLen))
		self.fields["NegThisMechASNLen"] = StructWithLen("<B", len(MechTypeLen)-2)
		#self.fields["NegThisMech1ASNLen"] = StructWithLen("<B", len(str(self.fields["NegThisMech1ASNStr"])))
		self.fields["NegThisMech2ASNLen"] = StructWithLen("<B", len(str(self.fields["NegThisMech2ASNStr"])))
		self.fields["NegThisMech3ASNLen"] = StructWithLen("<B", len(str(self.fields["NegThisMech3ASNStr"])))
		self.fields["NegThisMech4ASNLen"] = StructWithLen("<B", len(str(self.fields["NegThisMech4ASNStr"])))
		self.fields["NegThisMech5ASNLen"] = StructWithLen("<B", len(str(self.fields["NegThisMech5ASNStr"])))
		self.fields["NegTokenTag3ASNLen"] = StructWithLen("<B", len(Tag3Len))
		self.fields["NegHintASNLen"] = StructWithLen("<B", len(Tag3Len)-2)
		self.fields["NegHintTag0ASNLen"] = StructWithLen("<B", len(Tag3Len)-4)
		self.fields["NegHintFinalASNLen"] = StructWithLen("<B", len(str(self.fields["NegHintFinalASNStr"])))

class SMB2Session1Data(Packet):
	fields = OrderedDict([
		("Len",             "\x09\x00"),
		("SessionFlag",     "\x00\x00"),
		("SecBlobOffSet",   "\x48\x00"),
		("SecBlobLen",      "\x06\x01"),
		("ChoiceTagASNId",        "\xa1"), 
		("ChoiceTagASNLenOfLen",  "\x82"), 
		("ChoiceTagASNIdLen",     "\x01\x02"),
		("NegTokenTagASNId",      "\x30"),
		("NegTokenTagASNLenOfLen","\x81"),
		("NegTokenTagASNIdLen",   "\xff"),
		("Tag0ASNId",             "\xA0"),
		("Tag0ASNIdLen",          "\x03"),
		("NegoStateASNId",        "\x0A"),
		("NegoStateASNLen",       "\x01"),
		("NegoStateASNValue",     "\x01"),
		("Tag1ASNId",             "\xA1"),
		("Tag1ASNIdLen",          "\x0c"),
		("Tag1ASNId2",            "\x06"),
		("Tag1ASNId2Len",         "\x0A"),
		("Tag1ASNId2Str",         "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
		("Tag2ASNId",             "\xA2"),
		("Tag2ASNIdLenOfLen",     "\x81"),
		("Tag2ASNIdLen",          "\xE9"),
		("Tag3ASNId",             "\x04"),
		("Tag3ASNIdLenOfLen",     "\x81"),
		("Tag3ASNIdLen",          "\xE6"),
		("NTLMSSPSignature",      "NTLMSSP"),
		("NTLMSSPSignatureNull",  "\x00"),
		("NTLMSSPMessageType",    "\x02\x00\x00\x00"),
		("NTLMSSPNtWorkstationLen","\x1e\x00"),
		("NTLMSSPNtWorkstationMaxLen","\x1e\x00"),
		("NTLMSSPNtWorkstationBuffOffset","\x38\x00\x00\x00"),
		("NTLMSSPNtNegotiateFlags","\x15\x82\x81\xe2" if settings.Config.NOESS_On_Off else "\x15\x82\x89\xe2"),
		("NTLMSSPNtServerChallenge","\x81\x22\x33\x34\x55\x46\xe7\x88"),
		("NTLMSSPNtReserved","\x00\x00\x00\x00\x00\x00\x00\x00"),
		("NTLMSSPNtTargetInfoLen","\x94\x00"),
		("NTLMSSPNtTargetInfoMaxLen","\x94\x00"),
		("NTLMSSPNtTargetInfoBuffOffset","\x56\x00\x00\x00"),
		("NegTokenInitSeqMechMessageVersionHigh","\x06"),
		("NegTokenInitSeqMechMessageVersionLow","\x03"),
		("NegTokenInitSeqMechMessageVersionBuilt","\x80\x25"),
		("NegTokenInitSeqMechMessageVersionReserved","\x00\x00\x00"),
		("NegTokenInitSeqMechMessageVersionNTLMType","\x0f"),
		("NTLMSSPNtWorkstationName",settings.Config.Domain),
		("NTLMSSPNTLMChallengeAVPairsId","\x02\x00"),
		("NTLMSSPNTLMChallengeAVPairsLen","\x0a\x00"),
		("NTLMSSPNTLMChallengeAVPairsUnicodeStr",settings.Config.Domain),
		("NTLMSSPNTLMChallengeAVPairs1Id","\x01\x00"),
		("NTLMSSPNTLMChallengeAVPairs1Len","\x1e\x00"),
		("NTLMSSPNTLMChallengeAVPairs1UnicodeStr",settings.Config.MachineName), 
		("NTLMSSPNTLMChallengeAVPairs2Id","\x04\x00"),
		("NTLMSSPNTLMChallengeAVPairs2Len","\x1e\x00"),
		("NTLMSSPNTLMChallengeAVPairs2UnicodeStr",settings.Config.MachineName+'.'+settings.Config.DomainName), 
		("NTLMSSPNTLMChallengeAVPairs3Id","\x03\x00"),
		("NTLMSSPNTLMChallengeAVPairs3Len","\x1e\x00"),
		("NTLMSSPNTLMChallengeAVPairs3UnicodeStr", settings.Config.DomainName),
		("NTLMSSPNTLMChallengeAVPairs5Id","\x05\x00"),
		("NTLMSSPNTLMChallengeAVPairs5Len","\x04\x00"),
		("NTLMSSPNTLMChallengeAVPairs5UnicodeStr",settings.Config.DomainName),
		("NTLMSSPNTLMChallengeAVPairs7Id","\x07\x00"),
		("NTLMSSPNTLMChallengeAVPairs7Len","\x08\x00"),
		("NTLMSSPNTLMChallengeAVPairs7UnicodeStr",SMBTime()),
		("NTLMSSPNTLMChallengeAVPairs6Id","\x00\x00"),
		("NTLMSSPNTLMChallengeAVPairs6Len","\x00\x00"),
	])


	def calculate(self):
		###### Convert strings to Unicode
		self.fields["NTLMSSPNtWorkstationName"] = self.fields["NTLMSSPNtWorkstationName"].encode('utf-16le').decode('latin-1')
		self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"].encode('utf-16le').decode('latin-1')
		self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"].encode('utf-16le').decode('latin-1')
		self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"].encode('utf-16le').decode('latin-1')
		self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"].encode('utf-16le').decode('latin-1')
		self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"].encode('utf-16le').decode('latin-1')
		# Packet struct calc:
		StructLen = str(self.fields["Len"])+str(self.fields["SessionFlag"])+str(self.fields["SecBlobOffSet"])+str(self.fields["SecBlobLen"])
		###### SecBlobLen Calc:
		CalculateSecBlob = str(self.fields["NTLMSSPSignature"])+str(self.fields["NTLMSSPSignatureNull"])+str(self.fields["NTLMSSPMessageType"])+str(self.fields["NTLMSSPNtWorkstationLen"])+str(self.fields["NTLMSSPNtWorkstationMaxLen"])+str(self.fields["NTLMSSPNtWorkstationBuffOffset"])+str(self.fields["NTLMSSPNtNegotiateFlags"])+str(self.fields["NTLMSSPNtServerChallenge"])+str(self.fields["NTLMSSPNtReserved"])+str(self.fields["NTLMSSPNtTargetInfoLen"])+str(self.fields["NTLMSSPNtTargetInfoMaxLen"])+str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])+str(self.fields["NTLMSSPNtWorkstationName"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs7Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs7Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs7UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])
		AsnLen = str(self.fields["ChoiceTagASNId"])+str(self.fields["ChoiceTagASNLenOfLen"])+str(self.fields["ChoiceTagASNIdLen"])+str(self.fields["NegTokenTagASNId"])+str(self.fields["NegTokenTagASNLenOfLen"])+str(self.fields["NegTokenTagASNIdLen"])+str(self.fields["Tag0ASNId"])+str(self.fields["Tag0ASNIdLen"])+str(self.fields["NegoStateASNId"])+str(self.fields["NegoStateASNLen"])+str(self.fields["NegoStateASNValue"])+str(self.fields["Tag1ASNId"])+str(self.fields["Tag1ASNIdLen"])+str(self.fields["Tag1ASNId2"])+str(self.fields["Tag1ASNId2Len"])+str(self.fields["Tag1ASNId2Str"])+str(self.fields["Tag2ASNId"])+str(self.fields["Tag2ASNIdLenOfLen"])+str(self.fields["Tag2ASNIdLen"])+str(self.fields["Tag3ASNId"])+str(self.fields["Tag3ASNIdLenOfLen"])+str(self.fields["Tag3ASNIdLen"])
		#Packet Struct len
		self.fields["Len"] = StructWithLen("<h",len(StructLen)+1)
		self.fields["SecBlobLen"] = StructWithLen("<H", len(AsnLen+CalculateSecBlob))
		self.fields["SecBlobOffSet"] = StructWithLen("<h",len(StructLen)+64)
		###### ASN Stuff
		if len(CalculateSecBlob) > 255:
			self.fields["Tag3ASNIdLen"] = StructWithLen(">H", len(CalculateSecBlob))
		else:
			self.fields["Tag3ASNIdLenOfLen"] = "\x81"
			self.fields["Tag3ASNIdLen"] = StructWithLen(">B", len(CalculateSecBlob))

		if len(AsnLen+CalculateSecBlob)-3 > 255:
			self.fields["ChoiceTagASNIdLen"] = StructWithLen(">H", len(AsnLen+CalculateSecBlob)-4)
		else:
			self.fields["ChoiceTagASNLenOfLen"] = "\x81"
			self.fields["ChoiceTagASNIdLen"] = StructWithLen(">B", len(AsnLen+CalculateSecBlob)-3)
		if len(AsnLen+CalculateSecBlob)-7 > 255:
			self.fields["NegTokenTagASNIdLen"] = StructWithLen(">H", len(AsnLen+CalculateSecBlob)-8)
		else:
			self.fields["NegTokenTagASNLenOfLen"] = "\x81"
			self.fields["NegTokenTagASNIdLen"] = StructWithLen(">B", len(AsnLen+CalculateSecBlob)-7)
		tag2length = CalculateSecBlob+str(self.fields["Tag3ASNId"])+str(self.fields["Tag3ASNIdLenOfLen"])+str(self.fields["Tag3ASNIdLen"])
		if len(tag2length) > 255:
			self.fields["Tag2ASNIdLen"] = StructWithLen(">H", len(tag2length))
		else:
			self.fields["Tag2ASNIdLenOfLen"] = "\x81"
			self.fields["Tag2ASNIdLen"] = StructWithLen(">B", len(tag2length))
		self.fields["Tag1ASNIdLen"] = StructWithLen(">B", len(str(self.fields["Tag1ASNId2"])+str(self.fields["Tag1ASNId2Len"])+str(self.fields["Tag1ASNId2Str"])))
		self.fields["Tag1ASNId2Len"] = StructWithLen(">B", len(str(self.fields["Tag1ASNId2Str"])))
		###### Workstation Offset
		CalculateOffsetWorkstation = str(self.fields["NTLMSSPSignature"])+str(self.fields["NTLMSSPSignatureNull"])+str(self.fields["NTLMSSPMessageType"])+str(self.fields["NTLMSSPNtWorkstationLen"])+str(self.fields["NTLMSSPNtWorkstationMaxLen"])+str(self.fields["NTLMSSPNtWorkstationBuffOffset"])+str(self.fields["NTLMSSPNtNegotiateFlags"])+str(self.fields["NTLMSSPNtServerChallenge"])+str(self.fields["NTLMSSPNtReserved"])+str(self.fields["NTLMSSPNtTargetInfoLen"])+str(self.fields["NTLMSSPNtTargetInfoMaxLen"])+str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
		###### AvPairs Offset
		CalculateLenAvpairs = str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs7Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs7Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs7UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])
		##### Workstation Offset Calculation:
		self.fields["NTLMSSPNtWorkstationBuffOffset"] = StructWithLen("<i", len(CalculateOffsetWorkstation))
		self.fields["NTLMSSPNtWorkstationLen"] = StructWithLen("<h", len(str(self.fields["NTLMSSPNtWorkstationName"])))
		self.fields["NTLMSSPNtWorkstationMaxLen"] = StructWithLen("<h", len(str(self.fields["NTLMSSPNtWorkstationName"])))
		##### Target Offset Calculation:
		self.fields["NTLMSSPNtTargetInfoBuffOffset"] = StructWithLen("<i", len(CalculateOffsetWorkstation+str(self.fields["NTLMSSPNtWorkstationName"])))
		self.fields["NTLMSSPNtTargetInfoLen"] = StructWithLen("<h", len(CalculateLenAvpairs))
		self.fields["NTLMSSPNtTargetInfoMaxLen"] = StructWithLen("<h", len(CalculateLenAvpairs))
		##### IvPair Calculation:
		self.fields["NTLMSSPNTLMChallengeAVPairs7Len"] = StructWithLen("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs7UnicodeStr"])))
		self.fields["NTLMSSPNTLMChallengeAVPairs5Len"] = StructWithLen("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])))
		self.fields["NTLMSSPNTLMChallengeAVPairs3Len"] = StructWithLen("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])))
		self.fields["NTLMSSPNTLMChallengeAVPairs2Len"] = StructWithLen("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])))
		self.fields["NTLMSSPNTLMChallengeAVPairs1Len"] = StructWithLen("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])))
		self.fields["NTLMSSPNTLMChallengeAVPairsLen"] = StructWithLen("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])))

class SMB2Session2Data(Packet):
	fields = OrderedDict([
		("Len",             "\x09\x00"),
		("SessionFlag",     "\x00\x00"),
		("SecBlobOffSet",   "\x00\x00\x00\x00"),
    ])
