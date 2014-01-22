from pyparsing import Literal, Word, alphanums, nums, Forward, ZeroOrMore
import re

var_cnt = 0
var_constraint_dic = None
var_input_dic = None
var_size_dic = None
valgrind_operations = None
var_shift_dic = None
var_realsize_dic = None

def new_var():
	global var_cnt
	var_cnt += 1
	return '_%d' % var_cnt

def resize(oldvar, oldsize, newsize, l):
	global var_size_dic	
	
	newvar = new_var()
	var_size_dic[newvar] = newsize
	l.append(('assign', newvar, oldvar, (oldsize,newsize)))
	
	return newvar

def check_operand_size(operand, operation_size, l):
	global var_size_dic	
	
	if operand in var_size_dic:
		operand_size = int(var_size_dic[operand])
		if operand_size != operation_size:
			operand = resize(operand, operand_size, operation_size, l)
	
	return operand

def check_operands_size():
	global valgrind_operations, var_size_dic	
	valgrind_op_after_resize = []
	
	for valgrind_operation in valgrind_operations:
		operation, first_operand, second_operand, dest_operand = valgrind_operation
		
		m = re.match('(Add|Sub|Mul|DivModS\d+to)(\d+)', operation)
		if m:
			first_operand = check_operand_size(first_operand, int(var_size_dic[dest_operand]), valgrind_op_after_resize)
			second_operand = check_operand_size(second_operand, int(var_size_dic[dest_operand]), valgrind_op_after_resize)
		
		valgrind_op_after_resize.append((operation, first_operand, second_operand, dest_operand))
		
	valgrind_operations = valgrind_op_after_resize
	
def add_operation(operation, first_operand, second_operand, dest_operand, constraint):
	global valgrind_operations, var_constraint_dic
	
	valgrind_operations.append((operation, first_operand, second_operand, dest_operand))
	var_constraint_dic[dest_operand] = constraint

def parse_function(s, loc, toks):
	global var_constraint_dic, var_input_dic, var_size_dic, var_realsize_dic
	
	operation = toks[0]
	string = ''.join(toks)
	
	m = re.match('^INPUT\((\d+)\)$', string)
	if m:
		newvar = new_var()
		var_constraint_dic[newvar] = string
		var_input_dic[newvar] = int(m.group(1))
		return
		
	for var, constraint in var_constraint_dic.iteritems():
		m = re.match('^[a-zA-Z0-9:_]+\(%s\)$'%re.escape(constraint), string)
		if m:
			m = re.match('^LDle:(\d+)$', operation)
			if m:
				if var not in var_size_dic:
					var_size_dic[var] = int(m.group(1))
				var_realsize_dic[var] = int(m.group(1))
			
			add_operation(operation, var, None, var, string)			
			return
			
		m = re.match('^[a-zA-Z0-9:_]+\(%s,(\d+)\)$'%re.escape(constraint), string)
		if m:
			mm = re.match('^Shr\d+_$', operation)
			if mm:
				var_shift_dic[var] = int(m.group(1))
		
			dest_operand = new_var() if re.match('(Add|Sub|Mul|DivModS\d+to)\d+', operation) else var
			add_operation(operation, var, m.group(1), dest_operand, string)
			return		
		m = re.match('^[a-zA-Z0-9:_]+\((\d+),%s\)$'%re.escape(constraint), string)
		if m:
			dest_operand = new_var() if re.match('(Add|Sub|Mul|DivModS\d+to)\d+', operation) else var
			add_operation(operation, m.group(1), var, dest_operand, string)
			return
			
	for var1,constraint1 in var_constraint_dic.iteritems():
		for var2,constraint2 in var_constraint_dic.iteritems():
			m = re.match('^[a-zA-Z0-9:]+\(%s,%s\)$'%(re.escape(constraint1),re.escape(constraint2)), string)
			if m:
				add_operation(operation, var1, var2, new_var(), string)
				return
				
def init():
	global var_cnt, var_constraint_dic, var_input_dic, var_size_dic
	global valgrind_operations, var_shift_dic, var_realsize_dic
	
	var_cnt = 0
	var_constraint_dic = {}
	var_input_dic = {}
	var_size_dic = {}
	valgrind_operations = []
	var_shift_dic = {}
	var_realsize_dic = {}
	
def parse_constraint(constraint):
	global var_realsize_dic, var_shift_dic, var_input_dic, var_size_dic, valgrind_operations
	
	init()

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
	
	return (var_realsize_dic, var_shift_dic, var_input_dic, var_size_dic, valgrind_operations)
