import os
import subprocess
import re

valgrind_lib = '/home/fanatic/valgrind-3.8.1/inst/lib/valgrind/'
valgrind_outfile = 'out.txt'

def run(target):
	global valgrind_lib, valgrind_outfile
	
	outfile = open(valgrind_outfile, 'w')
	env = dict(os.environ)
	env['VALGRIND_LIB'] = valgrind_lib
	
	subprocess.call([
		'valgrind',
		'--tool=fuzzer',
		target
	], stderr=outfile, env=env)
	
	outfile.close()
	
def parse_outfile():
	global valgrind_outfile

	with open(valgrind_outfile, 'r') as f:
		constraints = [m.group(1) for m in (re.match('^branch: (.+)$', line) for line in f) if m]
	
	return constraints
	
X86Condcode = {
	2 : 'CmpLTU',
	6 : 'CmpLEU',
	12 : 'CmpLTS',
	14 : 'CmpLES'
}

class Operation:
	def __init__(self, operation, first_op, second_op, dest_op):
		self.operation = operation
		self.first_op = first_op
		self.second_op = second_op
		self.dest_op = dest_op

	def to_z3(self):
		return getattr(self, self.operation)()
		
	def z3_binop(self, op):
		return '%s = %s %s %s' % (self.dest_op, self.first_op, op, self.second_op)
	def z3_binop_unsigned(self, op):
		return '%s = %s(%s, %s)' % (self.dest_op, op, self.first_op, self.second_op)
		
	def z3_cmp(self, op):
		return self.z3_cmp_negate(op) if self.dest_op else 's.add(%s %s %s)' % (self.first_op, op, self.second_op)
	def z3_cmp_unsigned(self, op):
		return self.z3_cmp_unsigned_negate(op) if self.dest_op else 's.add(%s(%s, %s))' % (op, self.first_op, self.second_op)
	
	def z3_cmp_negate(self, op):
		return 's.add(Not(%s %s %s))' % (self.first_op, op, self.second_op)
	def z3_cmp_unsigned_negate(self, op):
		return 's.add(Not(%s(%s, %s)))' % (op, self.first_op, self.second_op)

	def Add(self):
		return self.z3_binop('+')
	def Sub(self):
		return self.z3_binop('-')
	def Mul(self):
		return self.z3_binop('*')
	def Or(self):
		return self.z3_binop('|')
	def And(self):
		return self.z3_binop('&')
	def Xor(self):
		return self.z3_binop('^')
	def Shl(self):
		return self.z3_binop('<<')
	def CmpEQ(self):
		return self.z3_cmp('==')
	def CmpNE(self):
		return self.z3_cmp('!=')
		
	def DivModS(self):
		return self.z3_binop('/')
	def Shr(self):
		return self.z3_binop('>>')
	def CmpLTS(self):
		return self.z3_cmp('<')
	def CmpLES(self):
		return self.z3_cmp('<=')
	def CmpGTS(self):
		return self.z3_cmp('>')
	def CmpGES(self):
		return self.z3_cmp('>=')
	
	def DivModU(self):
		return self.z3_binop_unsigned('UDiv')
	def Sar(self):
		return self.z3_binop_unsigned('LShR')
	def CmpLTU(self):
		return self.z3_cmp_unsigned('ULT')
	def CmpLEU(self):
		return self.z3_cmp_unsigned('ULE')
	def CmpGTU(self):
		return self.z3_cmp_unsigned('UGT')
	def CmpGEU(self):
		return self.z3_cmp_unsigned('UGE')
		
	'''	
		c = a/b: 64to32(DivModS64to32(32HLto64(Sar32(a,31), a), b))
	'''
	def HLto(self):
		return '%s = %s' % (self.dest_op, self.second_op)

