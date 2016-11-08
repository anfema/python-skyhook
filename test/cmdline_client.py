import argparse
import skyhook

parser = argparse.ArgumentParser(description='Make a location request against the skyhook service')
parser.add_argument(
	'-k', '--key',
	dest='key',
	action='store',
	nargs=1,
	type=str,
	required=True,
    help='encryption key from Skyhook API panel'
)

parser.add_argument(
	'-u', '--user',
	dest='userID',
	action='store',
	nargs=1,
	type=int,
	required=True,
    help='user ID from Skyhook API panel'
)

parser.add_argument(
	'-w', '--wifi',
	dest='wifi',
	action='append',
	nargs=1,
	type=str,
    help='WIFI BSSID and signal strength (format: XX:XX:XX:XX:XX:XX@RSSI)'
)

parser.add_argument(
	'-g', '--gps',
	dest='gps',
	action='store',
	nargs=1,
	type=str,
    help='GPS coordinate (format: lattitude,longitude@num_satelites)'
)

parser.add_argument(
	'-c', '--cell', '--celltower',
	dest='cell',
	action='append',
	nargs=1,
	type=str,
    help='Celltower information (format: MCC,MNC,LAC,CellID@RSSI)'
)

parser.add_argument(
	'-b', '--bt', '--bluetooth',
	dest='bt',
	action='append',
	nargs=1,
	type=str,
    help='Bluetooth beacon (format: XX:XX:XX:XX:XX:XX,UUID,Major,Minor@RSSI)'
)

args = parser.parse_args()

request = skyhook.SkyhookRequest()

if args.wifi:
	for wifi in args.wifi:
		wifi = wifi[0].replace(':', '')
		bssid, rssi = wifi.split('@')
		request.addAccessPoint(bssid, int(rssi))

if args.gps:
	coordinate, numSat = args.gps.split('@')
	lat, lon = coordinate.split(',')
	request.setGPSCoordinate(float(lat), float(lon), int(numSat))

if args.cell:
	for cell in args.cell:
		tower, rssi = cell[0].split('@')
		mcc, mnc, lac, cellID = tower.split(',')
		request.addGSMCellTower(int(lac), int(cellID), int(rssi), mcc=int(mcc), mnc=int(mnc))

if args.bt:
	for bt in args.bt:
		beacon, rssi = bt[0].split('@')
		mac, uuid, major, minor = beacon.split(',')
		request.addBluetoothMarker(int(major), int(minor), mac.replace(':', ''), uuid, int(rssi))

print('Performing request:', str(request))

connection = skyhook.SkyhookConnection(key=args.key[0], userID=int(args.userID[0]))
response = connection.performRequest(request)
if response.status != 'Ok':
	print('Error:', response.status)
else:
	print('Response: ', response.coordinate())
