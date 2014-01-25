import commands
import struct
import valgrind
import parser
import _z3

test_file = ''
test_bin = ''

def alter_file(offsets_values_sizes):
	global test_file
	
	commands.getoutput('echo "AAAAAAAAAAAAAAAA" > %s' % test_file)

	for offset, value, size in offsets_values_sizes:
		print '%s[%d] = %d (%d)' % (test_file, offset, value, size)
		
		with open(test_file,'r+b') as f:
			f.seek(offset)
			
			if size == 8:
				f.write(struct.pack('<B', value))
			elif size == 16:
				f.write(struct.pack('<H', value))
			elif size == 32:
				f.write(struct.pack('<I', value))

def process_constraint(constraint):
	global test_bin

	valgrind_operations, size_by_var, offset_by_var, realsize_by_var, shift_by_var = parser.parse_constraint(constraint)
	
	_z3.dump(valgrind_operations, size_by_var)	
	offsets_values_sizes = _z3.solve(offset_by_var, size_by_var, realsize_by_var, shift_by_var)
	
	alter_file(offsets_values_sizes)
	print commands.getoutput(test_bin)

def process_constraints(constraints):
	for constraint in constraints:
		process_constraint(constraint)

def lead(target, infile):
	global test_bin, test_file
	
	test_bin = target
	test_file = infile

	commands.getoutput('echo "AAAAAAAAAAAAAAAA" > %s' % test_file)
	valgrind.run(target)
	constraints = valgrind.parse_outfile()
	'''
	constraints = ['']
	'''
	process_constraints(constraints)

