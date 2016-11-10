import binascii
import datetime
import struct
from Crypto.Cipher import AES

from .util import fletcher16

class InvalidDataError(RuntimeError):
	"""
	Error class raised when the payload received from the Skyhook server is somehow corrupt
	"""

	pass

class SkyhookResponse:
	"""
	Response deserializer class
	"""

	#
	# Public API
	#

	def __init__(self, data, key):
		"""
		Initialize the response class with data

		:param data: the data from the Skyhook response
		:param key: the decryption key from the API console
		"""

		if not key:
			raise RuntimeError('No encryption key set')
		if not data:
			raise RuntimeError('No response data set')

		self.data = data
		self.key = binascii.unhexlify(key)
		self.status = 'Undefined'
		self.lat = None
		self.lon = None
		self.date = None
		self.deserialize()

	@property
	def coordinate(self):
		"""
		Fetch coordinate

		:return: Coordinate tuple (lat,long) if payload was not an error, else ``None``
		"""
		if self.status == 'Ok':
			return (self.lat, self.lon)
		else:
			return None

	#
	# Internal
	#

	def deserialize(self):
		"""
		Deserialize a response
		"""

		# unpack header
		(version, _, payload_len, IV) = struct.unpack('<BBh16s', self.data[:20])
		payload = self.data[20:]

		if len(payload) != payload_len + 2 or (len(payload) - 2) % 16 != 0:
			raise InvalidDataError('Payload length invalid: {} != {}'.format(len(payload), payload_len + 2))

		# AES decrypt
		decryptor = AES.new(self.key, AES.MODE_CBC, IV=IV)
		decrypted_payload = decryptor.decrypt(payload[:-2])

		# verify checksum (this seems inconsistent to request payload checksumming as it includes the header)
		crcp = fletcher16(self.data[:20] + decrypted_payload)
		crc = (payload[-1] << 8) + payload[-2]

		if crcp != crc:
			raise InvalidDataError('Checksum does not match: {} != {}'.format(crcp, crc))

		(serverVersion, timestamp, payloadType) = struct.unpack('<B6sB', decrypted_payload[:8])

		# decode timestamp
		dt = 0
		for char in timestamp[::-1]:
			dt = (dt << 8) + char
		self.date = datetime.datetime.fromtimestamp(dt/1000)

		# determine what is in the payload
		if payloadType == 10:  # LOCATION_RQ_ERROR
			self.status = 'Request error'
			return
		if payloadType == 11:  # LOCATION_GATEWAY_ERROR
			self.status = 'ELG Gateway error'
			return
		if payloadType == 12:  # LOCATION_API_ERROR
			self.status = 'API error'
			return
		if payloadType == 13:  # LOCATION_UNKNOWN
			self.status = 'Unknown error'
			return
		if payloadType == 20:  # LOCATION_UNABLE_TO_DETERMINE
			self.status = 'Insufficient data to calculate position'
			return

		if payloadType == 1:  # LOCATION_RQ_SUCCESS
			self.decodeLocationRQ(decrypted_payload[8:])

		if payloadType == 2:  # LOCATION_RQ_ADDR_SUCCESS
			self.decodeLocationRQAddr(decrypted_payload[8:])

	def decodeLocationRQ(self, data):
		"""
		Decode a Location response packet

		:param data: data to decode
		"""
		if data[0] != 0x08:  # DATA_TYPE_LAT_LON
			self.status = 'Invalid data'
			return

		if data[1] != 24: # size field
			self.status = 'Invalid data'
			return

		(lat, lon, hpe, dist) = struct.unpack(
			'<ddff',
			data[2:26],
		)

		self.status = 'Ok'
		self.lat = lat
		self.lon = lon
		self.hpe = hpe
		self.dist = dist

	def decodeLocationRQAddr(self, data):
		"""
		Decode a Location with address response packet

		:param data: data to decode
		"""

		# TODO: Implement full location response
		pass