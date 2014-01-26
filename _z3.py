import re
import commands
import valgrind

z3_file = 'out.py'

z3_prologue = '''
from z3 import *

s = Solver()
'''

z3_epilogue = '''
if s.check() == sat:
	# print s
	print s.model()
'''

def assign(lhs_op, rhs_op, oldsize_newsize_and_signedness, z3_operations):
	oldsize, newsize, signedness = oldsize_newsize_and_signedness
	
	if newsize > oldsize:
		if signedness == 'S':
			z3_operations.append('%s = SignExt(%d, %s)' % (lhs_op, newsize-oldsize, rhs_op))
		else:
			z3_operations.append('%s = ZeroExt(%d, %s)' % (lhs_op, newsize-oldsize, rhs_op))
	else:
		z3_operations.append('%s = Extract(%d, %d, %s)' % (lhs_op, newsize-1, 0, rhs_op))
		
def translate_valgrind_operations(valgrind_operations):
	z3_operations = []
	
	for i, (operation, first_op, second_op, dest_op) in enumerate(valgrind_operations):	
		if operation == 'assign':
			assign(first_op, second_op, dest_op, z3_operations)
			continue
			
		m = re.match('(Add|Sub|Mul|Shl|Shr|Sar|Div(?:Mod)?[S|U]|Or|And|Xor)\d+', operation)
		if m:
			z3_operations.append(valgrind.Operation(m.group(1), first_op, second_op, dest_op).to_z3())
			continue
			
		m = re.match('\d+HLto\d+', operation)
		if m:
			z3_operations.append(valgrind.Operation('HLto', first_op, second_op, dest_op).to_z3())
			continue
			
		m = re.match('(Cmp(?:EQ|NE|LT|LE))\d+(S|U)?', operation)
		if m:
			op = m.group(1)+m.group(2) if m.group(2) else m.group(1)			
			negate_constraint = any(item[0] == 'Not_' for item in valgrind_operations[i:])			
			z3_operations.append(valgrind.Operation(op, first_op, second_op, negate_constraint).to_z3())
			return z3_operations
		
		if operation == 'x86g_calculate_condition':
			op = valgrind.X86Condcode[first_op]			
			negate_constraint = any(item[0] == 'Not_' for item in valgrind_operations[i:])	
			z3_operations.append(valgrind.Operation(op, second_op, dest_op, negate_constraint).to_z3())
			return z3_operations
	
def dump(valgrind_operations, size_by_var):
	global z3_file, z3_prologue, z3_epilogue
	
	z3_operations = translate_valgrind_operations(valgrind_operations)
	
	f = open(z3_file,'w')	
	f.write(z3_prologue+'\n')
	for var, size in size_by_var.iteritems():
		f.write("%s = BitVec('%s', %d)\n" % (var, var, size))
	f.write('\n')	
	for op in z3_operations:
		f.write(op+'\n')
	f.write(z3_epilogue)
	f.close()

def solve(offset_by_var, size_by_var, realsize_by_var, shift_by_var):
	global z3_file
	offsets_values_sizes = []

	res = commands.getoutput('python '+z3_file)
	print res
	
	if res:
		vars_and_values = res.split(',')
		for var_and_value in vars_and_values:
			m = re.search('(_\d+) = (\d+)', var_and_value)		
			if m:
				var = m.group(1)
				value = int(m.group(2))
				
				offset = offset_by_var[var]
				size = realsize_by_var.get(var, size_by_var[var])
				
				if var in shift_by_var:
					value >>= shift_by_var[var]
					offset += shift_by_var[var]/8
					
				offsets_values_sizes.append((offset, value, size))
	
	return offsets_values_sizes
