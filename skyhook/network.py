from socket import create_connection
from .response import SkyhookResponse


class SkyhookConnection:
	"""
	Skyhook server connection class.

	You may specify a custom server by supplying ``server`` and ``port``.
	If you only use one account on that connection you may specify your API Key ``key``
	and user id ``userID`` while initializing this
	"""

	def __init__(self, server='elg.skyhook.com', port=9755, key=None, userID=None):
		self.socket = create_connection((server, port))
		self.socket.setblocking(1)
		self.key = key
		self.userID = userID

	def performRequest(self, request):
		"""
		Perform a request on the connection and return the response, blocks until response received
		This may throw network and runtime errors when something goes wrong.

		:param request: the request to perform
		:return: ``SkyhookResponse`` object with the response
		"""
		self.socket.sendall(request.serialize(key=self.key, userID=self.userID))
		response = self.socket.recv(1024)
		return SkyhookResponse(response, self.key)