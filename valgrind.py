import os
import subprocess
import re

valgrind_lib = '/home/fanatic/valgrind-3.8.1/inst/lib/valgrind/'
valgrind_outfile = 'out.txt'

def run(target):
	global valgrind_lib, valgrind_outfile
	
	env = dict(os.environ)
	env['VALGRIND_LIB'] = valgrind_lib	
	devnull = open(os.devnull, 'w')
	outfile = open(valgrind_outfile, 'w')
	
	subprocess.call([
		'valgrind',
		'--tool=fuzzer',
		target
	], stdout=devnull, stderr=outfile, env=env)
	
	devnull.close()
	outfile.close()
	
def parse_outfile():
	global valgrind_outfile
	constraints = []

	with open(valgrind_outfile, 'r') as f:
		for line in f:
			m = re.match('^branch: (.+)$', line)
			if m:
				constraints.append(m.group(1))
	
	return constraints

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
	def z3_binop_func(self, op):
		return '%s = %s(%s,%s)' % (self.dest_op, op, self.first_op, self.second_op)

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
	def Shr(self):
		return self.z3_binop('>>')
	def Sar(self):
		return self.z3_binop_func('LShR')
	def Div(self):
		return self.z3_binop('/')
		
	def _32HLto64(self):
		return '%s = %s' % (self.dest_op, self.second_op)
