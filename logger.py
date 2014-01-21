import re
from valgrind_op import Valgrind_op

z3_prologue = '''
from z3 import *

s = Solver()
'''

z3_epilogue = '''
s.add(%s == %d)

print s
print s.check()
print s.model()
'''

z3_operations = []
		
def log_to_file(var_by_size, var_epilogue, size_epilogue):
	global z3_prologue, z3_operations, z3_epilogue

	print z3_prologue		
	
	for var,size in var_by_size.iteritems():
		print "%s = BitVec('%s', %d)" % (var, var, int(size))
	print		
	
	for op in z3_operations:
		print op	
	
	print z3_epilogue % (var_epilogue, size_epilogue)
	
def assign(dest_op, first_op, size):
	global z3_operations
	
	if size > 0:
		z3_operations.append('%s = ZeroExt(%d, %s)' % (dest_op, size, first_op))
	else:
		z3_operations.append('%s = Extract(%d, %d, %s)' % (dest_op, 31+size, 0, first_op))	

def log(var_by_size, valgrind_operations):
	global z3_operations
	
	for operation, first_op, second_op, dest_op in valgrind_operations:	
		if operation == 'assign':
			assign(first_op, second_op, dest_op)
			continue
		
		m = re.match('(Add|Sub|Mul|Or|And|Xor|Shl|Shr|Sar)\d+', operation)
		if m:
			z3_operations.append(Valgrind_op(m.group(1), first_op, second_op, dest_op).pp())
			continue
			
		m = re.match('32HLto64', operation)
		if m:
			z3_operations.append(Valgrind_op('_32HLto64', first_op, second_op, dest_op).pp())
			continue
			
		m = re.match('DivModS64to32', operation)
		if m:
			z3_operations.append(Valgrind_op('Div', first_op, second_op, dest_op).pp())
			continue
			
		m = re.match('CmpEQ\d+', operation)
		if m:
			break
			
	log_to_file(var_by_size, first_op, int(second_op))
