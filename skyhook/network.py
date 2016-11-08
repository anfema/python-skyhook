from socket import create_connection
from .response import SkyhookResponse


class SkyhookConnection:

	def __init__(self, server='elg.skyhookwireless.com', port=9755, key=None, userID=None):
		self.socket = create_connection((server, port))
		self.socket.setblocking(1)
		self.key = key
		self.userID = userID

	def performRequest(self, request):
		self.socket.sendall(request.serialize(key=self.key, userID=self.userID))
		response = self.socket.recv(1024)
		return SkyhookResponse(response, self.key)