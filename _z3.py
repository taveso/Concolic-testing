import re
import commands
import valgrind

z3_file = 'out.py'

z3_prologue = '''
from z3 import *

s = Solver()
'''

z3_epilogue = '''
s.add(%s == %d)

if s.check() == sat:
	# print s
	print s.model()
'''

def assign(dest_op, first_op, oldsize_and_newsize, z3_operations):
	oldsize, newsize = oldsize_and_newsize
	
	if newsize > oldsize:
		z3_operations.append('%s = ZeroExt(%d, %s)' % (dest_op, newsize-oldsize, first_op))
	else:
		z3_operations.append('%s = Extract(%d, %d, %s)' % (dest_op, newsize-1, 0, first_op))

def translate_valgrind_operations(valgrind_operations):
	z3_operations = []
	
	for operation, first_op, second_op, dest_op in valgrind_operations:	
		if operation == 'assign':
			assign(first_op, second_op, dest_op, z3_operations)
			continue
		
		m = re.match('(Add|Sub|Mul|Or|And|Xor|Shl|Shr|Sar)\d+', operation)
		if m:
			z3_operations.append(valgrind.Operation(m.group(1), first_op, second_op, dest_op).to_z3())
			continue
			
		m = re.match('32HLto64', operation)
		if m:
			z3_operations.append(valgrind.Operation('_32HLto64', first_op, second_op, dest_op).to_z3())
			continue
			
		m = re.match('DivModS64to32', operation)
		if m:
			z3_operations.append(valgrind.Operation('Div', first_op, second_op, dest_op).to_z3())
			continue
			
		m = re.match('Cmp.*', operation)
		if m:
			break
			
	return (z3_operations, first_op, int(second_op))
	
def dump(valgrind_operations, size_by_var):
	global z3_file, z3_prologue, z3_epilogue
	
	z3_operations, var_epilogue, size_epilogue = translate_valgrind_operations(valgrind_operations)
	
	f = open(z3_file,'w')	
	f.write(z3_prologue+'\n')
	for var, size in size_by_var.iteritems():
		f.write("%s = BitVec('%s', %d)\n" % (var, var, int(size)))
	f.write('\n')	
	for op in z3_operations:
		f.write(op+'\n')	
	f.write(z3_epilogue % (var_epilogue, size_epilogue))	
	f.close()

def solve(offset_by_var, realsize_by_var, shift_by_var):
	global z3_file
	offsets_values_oldsize_and_newsize = []

	res = commands.getoutput('python '+z3_file)
	print res
	
	if res:
		vars_and_values = res.split(',')
		for var_and_value in vars_and_values:
			m = re.search('(_\d+) = (\d+)', var_and_value)		
			if m:
				var = m.group(1)
				value = int(m.group(2))
				
				offset = int(offset_by_var[var])
				size = int(realsize_by_var[var])
				
				if var in shift_by_var:
					value >>= shift_by_var[var]
					offset += shift_by_var[var]/8
					
				offsets_values_oldsize_and_newsize.append((offset, value, size))
	
	return offsets_values_oldsize_and_newsize
