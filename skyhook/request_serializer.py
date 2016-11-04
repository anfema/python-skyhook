import binascii
import struct
from Crypto.Cipher import AES

from skyhook import __client_version__
from .util import fletcher16


class SkyhookRequest:

	#
	# Public API
	#

	def __init__(self, key, userID, mcc=None, mnc=None):
		self.version = __client_version__
		self.mac = binascii.unhexlify('CAFEBABECAFE')  # TODO: use actual mac
		self.payloadType = 1  # LOCATION_RQ
		self.aps = []
		self.cellTowers = []
		self.ble = []
		self.gpsCoordinate = None
		self.mcc = mcc
		self.mnc = mnc
		self.key = binascii.unhexlify(key)
		self.userID = userID

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

	def serialize(self):
		IV = self.makeIV()

		# protocol version
		packet = bytearray(b'\x01')

		# user id
		packet.append(self.userID.to_bytes(4, byteorder='big'))

		# Build payload
		payload = self.serializePayload()

		# AES encrypt
		encryptor = AES.new(self.key, AES.MODE_CBC, IV=IV)
		payload = encryptor.encrypt(payload)

		# payload length
		packet.append(len(payload).to_bytes(2, byteorder='big'))

		# IV
		packet.append(IV)

		# payload
		packet.append(payload)

		return packet

	#
	# Internal
	#

	def makeIV(self):
		return 16 * b'\x00'  # TODO: create actual random IV

	def serializePayload(self):
		payload = bytearray()

		# client sw version
		payload.append(self.version.to_bytes(1, byteorder='big'))

		# client mac
		payload.append(self.mac)

		# LOCATION_RQ
		payload.append(self.payloadType.to_bytes(1, byteorder='big'))

		# AP
		if len(self.aps) > 0:
			payload.append(self.serializeAP())

		# Bluetooth
		if len(self.ble) > 0:
			payload.append(self.serializeBLE())

		# Celltower
		if len(self.cellTowers) > 0:
			payload.append(self.serializeCellTower())

		# GPS
		if self.gpsCoordinate:
			payload.append(self.serializeGPS())

		# pad
		if not (len(payload) + 2) % 16 == 0:
			padding = 16 - ((len(payload) + 2) % 16)
			payload.append(padding * b'\x00')

		# checksum
		payload.append(fletcher16(payload).to_bytes(2, byteorder='big'))

		return payload

	def serializeAP(self):
		buffer = bytearray(b'\x01')  # DATA_TYPE_AP
		buffer.append(len(self.aps).to_bytes(1, byteorder='big'))
		for ap in self.aps:
			buffer.append(
				struct.pack(
					'6sb',
					ap['bssid'],
					ap['rssi']
				)
			)
		return buffer

	def serializeBLE(self):
		buffer = bytearray(b'\x07')  # DATA_TYPE_BLE
		buffer.append(len(self.ble).to_bytes(1, byteorder='big'))
		for bta in self.ble:
			buffer.append(
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
		buffer.append(len(self.cellTowers).to_bytes(1, byteorder='big'))
		for tower in self.cellTowers:
			buffer.append(
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
		buffer.append(b'\x01')  # exactly one coordinate
		buffer.append(
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