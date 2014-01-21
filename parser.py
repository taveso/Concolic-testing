from pyparsing import Literal, Word, alphanums, nums, Forward, ZeroOrMore
import re

var_cnt = 0
var_by_constraint = {}
var_by_input = {}
var_by_size = {}
valgrind_operations = []

def new_var():
	global var_cnt
	var_cnt += 1
	return '_%d' % var_cnt

def resize(oldvar, oldsize, newsize):
	global var_by_size, valgrind_operations
	
	newvar = new_var()
	var_by_size[newvar] = newsize
	valgrind_operations.append(('assign', newvar, oldvar, newsize-oldsize))
	
	return newvar
	
def check_operand_size(operand, operation_size):
	global var_by_size	
	
	if operand in var_by_size:
		operand_size = int(var_by_size[operand])
		if operand_size != operation_size:
			operand = resize(operand, operand_size, operation_size)
	
	return operand

def check_operands_size(first_operand, second_operand, dest_operand, operation_size):
	global var_by_size

	new_first_operand = check_operand_size(first_operand, operation_size)
	new_second_operand = check_operand_size(second_operand, operation_size)
	
	if first_operand == dest_operand:
		new_dest_operand = new_first_operand
	elif second_operand == dest_operand:
		new_dest_operand = new_second_operand
	else:
		new_dest_operand = dest_operand
		var_by_size[new_dest_operand] = operation_size
		
	return (new_first_operand, new_second_operand, new_dest_operand)
	
def get_final_operands(operation, first_operand, second_operand, dest_operand):
	m = re.match('(Add|Sub|Mul|Or|And|Xor|Shl|Shr|Sar|DivModS\d+to)(\d+)', operation)
	if m:
		first_operand, second_operand, dest_operand = check_operands_size(first_operand, second_operand, dest_operand, int(m.group(2)))
		
	return (first_operand, second_operand, dest_operand)

def add_operation(operation, first_operand, second_operand, dest_operand, constraint):
	global valgrind_operations, var_by_constraint
	
	first_operand, second_operand, dest_operand = get_final_operands(operation, first_operand, second_operand, dest_operand)
	valgrind_operations.append((operation, first_operand, second_operand, dest_operand))
	var_by_constraint[dest_operand] = constraint

def parse_function(s, loc, toks):
	global var_by_constraint, var_by_input, var_by_size
	
	operation = toks[0]
	string = ''.join(toks)
	
	m = re.match('^INPUT\((\d+)\)$', string)
	if m:
		newvar = new_var()
		var_by_constraint[newvar] = string
		var_by_input[newvar] = m.group(1)
		return
		
	for var,constraint in var_by_constraint.iteritems():
		m = re.match('^[a-zA-Z0-9:_]+\(%s\)$'%re.escape(constraint), string)
		if m:
			if (var in var_by_input) and (var not in var_by_size):
				m = re.match('^LDle:(\d+)$', operation)
				if m:
					var_by_size[var] = m.group(1)
			
			add_operation(operation, var, None, var, string)			
			return
		
		m = re.match('^[a-zA-Z0-9:]+\(%s,(\d+)\)$'%re.escape(constraint), string)
		if m:
			add_operation(operation, var, m.group(1), var, string)
			return
		m = re.match('^[a-zA-Z0-9:]+\((\d+),%s\)$'%re.escape(constraint), string)
		if m:
			add_operation(operation, m.group(1), var, var, string)
			return
			
	for var1,constraint1 in var_by_constraint.iteritems():
		for var2,constraint2 in var_by_constraint.iteritems():
			m = re.match('^[a-zA-Z0-9:]+\(%s,%s\)$'%(re.escape(constraint1),re.escape(constraint2)), string)
			if m:
				add_operation(operation, var1, var2, new_var(), string)
				return
	
def parse_constraint(constraint):
	global var_by_size, valgrind_operations

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
	
	return (var_by_size, valgrind_operations)
