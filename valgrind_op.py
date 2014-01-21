class Valgrind_op:
	def __init__(self, operation, first_op, second_op, dest_op):
		self.operation = operation
		self.first_op = first_op
		self.second_op = second_op
		self.dest_op = dest_op

	def pp(self):
		return getattr(self, self.operation)()
		
	def binop(self, op):
		return '%s = %s %s %s' % (self.dest_op, self.first_op, op, self.second_op)
	def binop_function(self, op):
		return '%s = %s(%s,%s)' % (self.dest_op, op, self.first_op, self.second_op)

	def Add(self):
		return self.binop('+')
	def Sub(self):
		return self.binop('-')
	def Mul(self):
		return self.binop('*')
	def Or(self):
		return self.binop('|')
	def And(self):
		return self.binop('&')
	def Xor(self):
		return self.binop('^')
	def Shl(self):
		return self.binop('<<')
	def Shr(self):
		return self.binop('>>')
	def Sar(self):
		return self.binop_function('LShR')
	def Div(self):
		return self.binop_function('UDiv')
		
	def _32HLto64(self):
		return '%s = %s' % (self.dest_op, self.second_op)
