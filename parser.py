from pyparsing import Literal, Word, alphanums, nums, Forward, ZeroOrMore
import re

var_cnt = 0
constraint_by_var = None
offset_by_var = None
realsize_by_var = None
shift_by_var = None
size_by_var = None
valgrind_operations = None

def new_var():
	global var_cnt
	var_cnt += 1
	return '_%d' % var_cnt

def resize(oldvar, oldsize, newsize, l):
	global size_by_var	
	
	newvar = new_var()
	size_by_var[newvar] = newsize
	l.append(('assign', newvar, oldvar, (oldsize,newsize)))
	
	return newvar

def check_operand_size(operand, operation_size, l):
	global size_by_var	
	
	if operand in size_by_var:
		operand_size = int(size_by_var[operand])
		if operand_size != operation_size:
			operand = resize(operand, operand_size, operation_size, l)
	
	return operand

def check_operands_size():
	global valgrind_operations, size_by_var	
	valgrind_op_after_resize = []
	
	for operation, first_operand, second_operand, dest_operand in valgrind_operations:		
		m = re.match('(Add|Sub|Mul|DivModS\d+to)(\d+)', operation)
		if m:
			first_operand = check_operand_size(first_operand, int(size_by_var[dest_operand]), valgrind_op_after_resize)
			second_operand = check_operand_size(second_operand, int(size_by_var[dest_operand]), valgrind_op_after_resize)
		
		valgrind_op_after_resize.append((operation, first_operand, second_operand, dest_operand))
		
	valgrind_operations = valgrind_op_after_resize
	
def add_operation(operation, first_operand, second_operand, dest_operand, constraint):
	global valgrind_operations, constraint_by_var
	
	valgrind_operations.append((operation, first_operand, second_operand, dest_operand))
	constraint_by_var[dest_operand] = constraint

def parse_function(s, loc, toks):
	global constraint_by_var, offset_by_var, size_by_var, realsize_by_var
	
	operation = toks[0]
	string = ''.join(toks)
	
	m = re.match('^INPUT\((\d+)\)$', string)
	if m:
		newvar = new_var()
		constraint_by_var[newvar] = string
		offset_by_var[newvar] = int(m.group(1))
		return
		
	for var, constraint in constraint_by_var.iteritems():
		m = re.match('^[a-zA-Z0-9:_]+\(%s\)$'%re.escape(constraint), string)
		if m:
			m = re.match('^LDle:(\d+)$', operation)
			if m:
				if var not in size_by_var:
					size_by_var[var] = int(m.group(1))
				realsize_by_var[var] = int(m.group(1))
			
			add_operation(operation, var, None, var, string)			
			return
			
		m = re.match('^[a-zA-Z0-9:_]+\(%s,(\d+)\)$'%re.escape(constraint), string)
		if m:
			mm = re.match('^Shr\d+_$', operation)
			if mm:
				shift_by_var[var] = int(m.group(1))
		
			dest_operand = new_var() if re.match('(Add|Sub|Mul|DivModS\d+to)\d+', operation) else var
			add_operation(operation, var, m.group(1), dest_operand, string)
			return		
		m = re.match('^[a-zA-Z0-9:_]+\((\d+),%s\)$'%re.escape(constraint), string)
		if m:
			dest_operand = new_var() if re.match('(Add|Sub|Mul|DivModS\d+to)\d+', operation) else var
			add_operation(operation, m.group(1), var, dest_operand, string)
			return
			
	for var1,constraint1 in constraint_by_var.iteritems():
		for var2,constraint2 in constraint_by_var.iteritems():
			m = re.match('^[a-zA-Z0-9:]+\(%s,%s\)$'%(re.escape(constraint1),re.escape(constraint2)), string)
			if m:
				add_operation(operation, var1, var2, new_var(), string)
				return
				
def init_global_vars():
	global var_cnt, constraint_by_var	
	global valgrind_operations, size_by_var, offset_by_var, realsize_by_var, shift_by_var
	
	var_cnt = 0
	constraint_by_var = {}
	offset_by_var = {}
	realsize_by_var = {}
	shift_by_var = {}
	size_by_var = {}
	valgrind_operations = []
	
def parse_constraint(constraint):
	global valgrind_operations, size_by_var, offset_by_var, realsize_by_var, shift_by_var
	
	init_global_vars()

	lparen = Literal("(")
	rparen = Literal(")")

	func = Word(alphanums, alphanums+":_")
	integer = Word(nums)

	expression = Forward()

	arg = expression | func | integer
	args = arg + ZeroOrMore(","+arg)

	expression << func + lparen + args + rparen	
	expression.setParseAction(parse_function)
	
	expression.parseString(constraint)
	
	check_operands_size()
	
	return (valgrind_operations, size_by_var, offset_by_var, realsize_by_var, shift_by_var)
