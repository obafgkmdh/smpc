from Crypto.Util.number import long_to_bytes, bytes_to_long
from hashlib import sha256
from secrets import randbits

BITS = 64

def get_key(k1, k2):
	key = sha256(long_to_bytes(k1)+long_to_bytes(k2)).digest()
	return bytes_to_long(key) % (1 << (BITS + 1))

class Circuit:
	GLOBAL_DELTA = randbits(BITS) << 1 | 1
	
	def __init__(self, l, r, bits, conjunction):
		self.l = l
		self.r = r
		self.conjunction = conjunction
		self.bits = bits
		
		# No table needed for XOR, though we still need to construct the output wire
		if self.bits == [0, 1, 1, 0]:
			l0 = l.out.labels[0] ^ r.out.labels[0]
			self.out = Wire(labels=[l0, l0 ^ self.GLOBAL_DELTA])
			return
		
		# create garbled table
		table = []
		labels = [None, None]
		for lb in [0, 1]:
			for rb in [0, 1]:
				key = get_key(l.out.labels[lb ^ l.out.ptr], r.out.labels[rb ^ r.out.ptr])
				if lb == 0 and rb == 0:
					# initialize labels with opposing pointer bits
					labels[bits[l.out.ptr << 1 ^ r.out.ptr]] = key
					labels[bits[l.out.ptr << 1 ^ r.out.ptr] ^ 1] = key ^ self.GLOBAL_DELTA
				else:
					out_label = labels[bits[(lb ^ l.out.ptr) << 1 ^ (rb ^ r.out.ptr)]]
					table.append(key ^ out_label)
		
		self.out = Wire(labels=labels)
		self.table = table
	
	def __and__(self, other):
		return Circuit(self, other, [0, 0, 0, 1], "&")
	
	def __or__(self, other):
		return Circuit(self, other, [0, 1, 1, 1], "|")
	
	def __xor__(self, other):
		return Circuit(self, other, [0, 1, 1, 0], "^")
	
	def __repr__(self):
		return f"({self.l} {self.conjunction} {self.r})"
	
	def _evaluate(self, values):
		# get label corresponding to a circuit evaluation
		left = self.l._evaluate(values)
		right = self.r._evaluate(values)
		
		if self.bits == [0, 1, 1, 0]:
			# XOR is free
			return left ^ right
		
		# extract pointer bits
		ptr_l = left & 1
		ptr_r = right & 1
		
		# decrypt corresponding row
		return get_key(left, right) ^ ([0] + self.table)[ptr_l << 1 ^ ptr_r]
	
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
			label_0 = randbits(BITS) << 1 ^ self.ptr
			self.labels = [label_0, label_0 ^ self.GLOBAL_DELTA]
		else:
			# set labels and extract pointer bit
			self.ptr = labels[0] & 1
			self.labels = labels
	
	def _evaluate(self, values):
		# Generator's input labels can be sent to the evaluator directly
		# Evaluator's inputs are retrieved using oblivious transfer (not implemented)
		return self.labels[values[self.name]]
	
	def __repr__(self):
		return self.name

a = Wire('a')
b = Wire('b')
c = Wire('c')
circuit = (a ^ b) & c

print(circuit.evaluate({'a': 0, 'b': 1, 'c': 1}))