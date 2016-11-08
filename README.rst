Skyhook ELG client for python
=============================

This implements the Skyhook ELG binary protocol in python

Installation
------------

Just install with ``pip``::

	pip install python-skyhook

Usage
-----

Python example::

	import skyhook

	key = 'ABCDEF1234567890'  # from the API console
	userID = 11111            # from the API console

	bssid = 'ab:cd:ef:12:34:56'
	rssi = -60

	request = skyhook.SkyhookRequest()
	request.addAccessPoint(bssid.replace(':', ''), rssi)

	connection = skyhook.SkyhookConnection(key=key, userID=userID)
	response = connection.performRequest(request)

	if response.status != 'Ok':
		print('Error:', response.status)
	else:
		print('Response: ', response.coordinate)

Command line client
-------------------

In the ``test`` directory you'll find a command line client to test if everything works::

	$ python cmdline_client.py --help
	usage: cmdline_client.py [-h] -k KEY -u USERID [-w WIFI] [-g GPS] [-c CELL]
							 [-b BT]

	Make a location request against the skyhook service

	optional arguments:
	  -h, --help            show this help message and exit
	  -k KEY, --key KEY     encryption key from Skyhook API panel
	  -u USERID, --user USERID
							user ID from Skyhook API panel
	  -w WIFI, --wifi WIFI  WIFI BSSID and signal strength (format: XX:XX:XX:XX:XX:XX@RSSI)
	  -g GPS, --gps GPS     GPS coordinate (format: latitude,longitude@num_satelites)
	  -c CELL, --cell CELL, --celltower CELL
							Celltower information (format: MCC,MNC,LAC,CellID@RSSI)
	  -b BT, --bt BT, --bluetooth BT
							Bluetooth beacon (format: XX:XX:XX:XX:XX:XX,UUID,Major,Minor@RSSI)
