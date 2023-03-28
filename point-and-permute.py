from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes, bytes_to_long
from hashlib import sha256
from secrets import randbits

BITS = 64

def encrypt(k1, k2, m):
	cipher = AES.new(sha256(long_to_bytes(k1)+long_to_bytes(k2)).digest(), AES.MODE_CBC)
	return cipher.iv + cipher.encrypt(pad(long_to_bytes(m), 16))
def decrypt(k1, k2, c):
	cipher = AES.new(sha256(long_to_bytes(k1)+long_to_bytes(k2)).digest(), AES.MODE_CBC, iv=c[:16])
	return bytes_to_long(unpad(cipher.decrypt(c[16:]), 16))

class Circuit:
	def __init__(self, l, r, bits, conjunction):
		self.left = l
		self.right = r
		self.conjunction = conjunction
		
		# create output wire
		self.out = Wire()
		
		# create garbled table
		table = []
		for lb in [0, 1]:
			for rb in [0, 1]:
				out_label = self.out.labels[bits[(lb ^ l.ptr) << 1 ^ (rb ^ r.ptr)]]
				table.append(encrypt(l.labels[lb ^ l.ptr], r.labels[rb ^ r.ptr], out_label))
		self.table = table
	
	def __and__(self, other):
		return Circuit(self, other, [0, 0, 0, 1], "&")
	
	def __or__(self, other):
		return Circuit(self, other, [0, 1, 1, 1], "|")
	
	def __xor__(self, other):
		return Circuit(self, other, [0, 1, 1, 0], "^")	
	
	def __repr__(self):
		return f"({self.left} {self.conjunction} {self.right})"
	
	def _evaluate(self, values):
		# get label corresponding to a circuit evaluation
		left = self.left._evaluate(values)
		right = self.right._evaluate(values)
		
		# extract pointer bits
		ptr_l = left & 1
		ptr_r = right & 1
		
		# decrypt corresponding row
		return decrypt(left, right, self.table[ptr_l << 1 ^ ptr_r])
	
	def evaluate(self, values):
		# Evaluator evaluates the circuit to get an output label
		out_label = self._evaluate(values)
		# Generator turns the label into a result
		return self.out.labels.index(out_label)

class Wire(Circuit):
	def __init__(self, name=None, labels=None):
		self.name = name
		self.out = self
		if labels is None:
			# generate pointer bit and labels
			self.ptr = randbits(1)
			self.labels = [randbits(BITS) << 1 ^ self.ptr, randbits(BITS) << 1 ^ (self.ptr ^ 1)]
		else:
			self.labels = labels
	
	def _evaluate(self, values):
		# Generator's input labels can be sent to the evaluator directly
		# Evaluator's inputs are retrieved using oblivious transfer (not implemented)
		return self.labels[values[self.name]]
	
	def __repr__(self):
		return self.name

a = Wire('a')
b = Wire('b')
c = a & b

print(c.evaluate({'a': 0, 'b': 1}))
