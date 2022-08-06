#!/usr/bin/env python
"""
@author    : ALIF FUSOBAR
@nickname  : Xcod3bughunt3r
@license   : MIT FUCK LICENSE
@contact   : master@itsecurity.id
"""

from utils import *
if settings.Config.PY2OR3 == "PY3":
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler

from packets import FTPPacket

class FTP(BaseRequestHandler):
	def handle(self):
		try:
			self.request.send(NetworkSendBufferPython2or3(FTPPacket()))
			data = self.request.recv(1024)

			if data[0:4] == b'USER':
				User = data[5:].strip().decode("latin-1")

				Packet = FTPPacket(Code="331",Message="User name okay, need password.")
				self.request.send(NetworkSendBufferPython2or3(Packet))
				data = self.request.recv(1024)

			if data[0:4] == b'PASS':
				Pass = data[5:].strip().decode("latin-1")

				Packet = FTPPacket(Code="530",Message="User not logged in.")
				self.request.send(NetworkSendBufferPython2or3(Packet))
				data = self.request.recv(1024)

				SaveToDb({
					'module': 'FTP', 
					'type': 'Cleartext', 
					'client': self.client_address[0], 
					'user': User, 
					'cleartext': Pass, 
					'fullhash': User + ':' + Pass
				})

			else:
				Packet = FTPPacket(Code="502",Message="Command not implemented.")
				self.request.send(NetworkSendBufferPython2or3(Packet))
				data = self.request.recv(1024)

		except Exception:
			pass
