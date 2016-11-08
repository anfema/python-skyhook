import binascii
import struct
from Crypto.Cipher import AES
from Crypto import Random

from skyhook import __client_version__
from .util import fletcher16


class SkyhookRequest:

	#
	# Public API
	#

	def __init__(self, key=None, userID=None, mcc=None, mnc=None):
		self.version = __client_version__
		self.mac = binascii.unhexlify('CAFEBABECAFE')  # TODO: use actual mac
		self.payloadType = 1  # LOCATION_RQ
		self.aps = []
		self.cellTowers = []
		self.ble = []
		self.gpsCoordinate = None
		self.mcc = mcc
		self.mnc = mnc
		if key:
			self.key = binascii.unhexlify(key)
		else:
			self.key = None
		self.userID = userID

	def __str__(self):
		return '<SkyhookRequest: {wifi} WIFI APs, {bt} Bluetooth markers, {tower} GSM towers{gps}>'.format(
			wifi=len(self.aps),
			bt=len(self.ble),
			tower=len(self.cellTowers),
			gps=', GPS: {lat}, {lon}'.format(lat=self.gpsCoordinate['lat'], lon=self.gpsCoordinate['lon']) if self.gpsCoordinate else ''
		)

	def addAccessPoint(self, BSSID, rssi):
		self.aps.append({
			'bssid': binascii.unhexlify(BSSID),
			'rssi': rssi
		})

	def addGSMCellTower(self, lac, cellID, rssi, mcc=None, mnc=None):
		if not self.mcc and not mcc:
			raise RuntimeError('Either set mcc on initialization or provide it when adding a cell tower')
		if not self.mnc and not mnc:
			raise RuntimeError('Either set mcc on initialization or provide it when adding a cell tower')
		if not mcc:
			mcc = self.mcc
		if not mnc:
			mnc = self.mnc

		self.cellTowers.append({
			'mcc': mcc,
			'mnc': mnc,
			'lac': lac,
			'cellID': cellID,
			'rssi': rssi
		})

	def addBluetoothMarker(self, major, minor, MAC, uuid, rssi):
		self.ble.append({
			'major': major,
			'minor': minor,
			'mac': binascii.unhexlify(MAC),
			'uuid': uuid,
			'rssi': rssi
		})

	def setGPSCoordinate(self, lat, lon, numSatelites, altitude=0, speed=0, hpe=0):
		self.gpsCoordinate = {
			'lat': lat,
			'lon': lon,
			'nsat': numSatelites,
			'alt': altitude,
			'speed': speed,
			'hpe': hpe
		}

	def serialize(self, key=None, userID=None):
		if key:
			self.key = binascii.unhexlify(key)
		if userID:
			self.userID = userID

		if not self.key:
			raise RuntimeError('No encryption key set')
		if not self.userID:
			raise RuntimeError('No user ID set')

		IV = self.makeIV()

		# protocol version
		packet = bytearray(b'\x01')

		# user id
		packet.extend(self.userID.to_bytes(4, byteorder='big'))

		# Build payload
		payload = self.serializePayload()

		# AES encrypt
		encryptor = AES.new(self.key, AES.MODE_CBC, IV=IV)
		payload = encryptor.encrypt(bytes(payload))

		# payload length
		packet.extend(len(payload).to_bytes(2, byteorder='big'))

		# IV
		packet.extend(IV)

		# payload
		packet.extend(payload)

		return packet

	#
	# Internal
	#

	def makeIV(self):
		return Random.new().read(AES.block_size)

	def serializePayload(self):
		payload = bytearray()

		# client sw version
		payload.extend(self.version.to_bytes(1, byteorder='big'))

		# client mac
		payload.extend(self.mac)

		# LOCATION_RQ
		payload.extend(self.payloadType.to_bytes(1, byteorder='big'))

		# AP
		if len(self.aps) > 0:
			payload.extend(self.serializeAP())

		# Bluetooth
		if len(self.ble) > 0:
			payload.extend(self.serializeBLE())

		# Celltower
		if len(self.cellTowers) > 0:
			payload.extend(self.serializeCellTower())

		# GPS
		if self.gpsCoordinate:
			payload.extend(self.serializeGPS())

		# pad
		if not (len(payload) + 2) % 16 == 0:
			padding = 16 - ((len(payload) + 2) % 16)
			payload.extend(padding * b'\x00')

		# checksum
		payload.extend(fletcher16(payload).to_bytes(2, byteorder='big'))

		return payload

	def serializeAP(self):
		buffer = bytearray(b'\x01')  # DATA_TYPE_AP
		buffer.extend(len(self.aps).to_bytes(1, byteorder='big'))
		for ap in self.aps:
			buffer.extend(
				struct.pack(
					'6sb',
					ap['bssid'],
					ap['rssi']
				)
			)
		return buffer

	def serializeBLE(self):
		buffer = bytearray(b'\x07')  # DATA_TYPE_BLE
		buffer.extend(len(self.ble).to_bytes(1, byteorder='big'))
		for bta in self.ble:
			buffer.extend(
				struct.pack(
					'HH6s16sb',
					bta['minor'],
					bta['major'],
					bta['mac'],
					bta['uuid'],
					bta['rssi']
				)
			)
		return buffer

	def serializeCellTower(self):
		buffer = bytearray(b'\x03')  # DATA_TYPE_GSM
		buffer.extend(len(self.cellTowers).to_bytes(1, byteorder='big'))
		for tower in self.cellTowers:
			buffer.extend(
				struct.pack(
					'IIHHHb',
					tower['cellID'],
					0,  # age
					tower['mcc'],
					tower['mnc'],
					tower['lac'],
					tower['rssi']
				)
			)
		return buffer

	def serializeGPS(self):
		buffer = bytearray(b'\x02')  # DATA_TYPE_GPS
		buffer.extend(b'\x01')  # exactly one coordinate
		buffer.extend(
			struct.pack(
				'ddffIfBB',
				self.gpsCoordinate['lat'],
				self.gpsCoordinate['lon'],
				self.gpsCoordinate['alt'],
				self.gpsCoordinate['hpe'],
				0,  # age
				self.gpsCoordinate['speed'],
				self.gpsCoordinate['nsat'],
				1,  # fix
			)
		)
		return buffer