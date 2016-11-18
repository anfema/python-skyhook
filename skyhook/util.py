def fletcher16(data):
	"""
	Calculate fletcher 16 checksum over data

	:param data: input data
	:return: 16 bit fletcher checksum
	"""

	s1 = 0
	s2 = 0
	for char in data:
		s1 += char
		s2 += s1
	s1 = s1 % 0xff
	s2 = s2 % 0xff
	return s2 << 8 | s1
