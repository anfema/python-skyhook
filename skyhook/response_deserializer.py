import binascii
import datetime
import struct
from Crypto.Cipher import AES

from skyhook import __client_version__
from .util import fletcher16

class InvalidDataError(RuntimeError):
	pass

class SkyhookResponse:

	#
	# Public API
	#

	def __init__(self, data, key):
		self.data = data
		self.key = key
		self.status = 'Undefined'
		self.lat = None
		self.lon = None
		self.date = None
		self.deserialize()

	def coordinate(self):
		return (self.lat, self.lon)

	#
	# Internal
	#

	def deserialize(self):
		# unpack header
		(version, payload_len, IV) = struct.unpack('B>h16s', self.data)
		payload = self.data[19:]

		if len(payload) != payload_len or len(payload) % 16 != 0:
			raise InvalidDataError('Payload length invalid')

		# AES decrypt
		decryptor = AES.new(self.key, AES.MODE_CBC, IV=IV)
		payload = decryptor.decrypt(payload)

		# verify checksum
		if fletcher16(payload[:-2]) != (payload[-2] << 8) + payload[-1]:
			raise InvalidDataError('Checksum does not match')

		(serverVersion, timestamp, payloadType) = struct.unpack('B6sB')

		# decode timestamp
		dt = 0
		for char in timestamp:
			dt = (dt << 8) + char
		self.date = datetime.datetime.fromtimestamp(dt)

		# determine what is in the payload
		if payloadType == 255:  # PAYLOAD_ERROR
			self.status = 'Binary format error'
			return
		if payloadType == 254:  # PAYLOAD_API_ERROR
			self.status = 'API Error'
			return
		if payloadType == 253:  # SERVER_ERROR
			self.status = 'Server error'
			return
		if payloadType == 252:  # LOCATION_RQ_ERROR
			self.status = 'Location RQ error'
			return

		if payloadType == 1:  # LOCATION_RQ
			self.decodeLocationRQ(payload[8:-2])

		if payloadType == 2:  # LOCATION_RQ_ADDR
			self.decodeLocationRQAddr(payload[8:-2])

	def decodeLocationRQ(self, data):
		if data[0] != 0x02:  # DATA_TYPE_GPS
			self.status = 'Invalid data'
			return

		(lat, lon, hpe) = struct.unpack_from(
			'ddf',
			data,
			offset=2
		)

		self.lat = lat
		self.lon = lon

	def decodeLocationRQAddr(self, data):
		# TODO: Implement full location response
		pass