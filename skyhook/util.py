
def fletcher16(data):
	"""
	Calculate fletcher 16 checksum over data

	:param data: input data
	:return: 16 bit fletcher checksum
	"""

	s1 = 0xff
	s2 = 0xff
	index = 0
	for char in data:
		s1 += char
		s2 += s1
		if index == 19:
			index = 0
			s1 = (s1 & 0xff) + (s1 >> 8)
			s2 = (s2 & 0xff) + (s2 >> 8)
		index += 1
	s1 = (s1 & 0xff) + (s1 >> 8)
	s2 = (s2 & 0xff) + (s2 >> 8)
	return s2 << 8 | s1