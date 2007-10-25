# string_token.py file is for handling all string related functionality
#Licence: GNU/GPL
#Authors: 
#Tao Wan<twan@cc.hut.fi>


#!/usr/bin/python
import shlex





"""
Take the whole string as a parameter, return a token strings
"""
def string_lexical(string_needs_parse):
	lexer = shlex.shlex(string_needs_parse)
	temp = []
	for token in lexer:
                temp.append(token)
		
	return temp



"""
simple counter for socket API, for a function call like 
function socket call, its previous chars should be ";"," = " , "nothing" or 
"}",its after_char should be char "(" 
"""
def simple_api_function_counter(api_name, token_list):
	#previous_chars = ""
	#after_chars = ""
	i = 0
	counter = 0
	
	length_list = len(token_list)

	
	#print length_list
	
	temp = token_list
	for strings in temp:
		
		if (i == 0):
			if (strings == api_name) and (temp[i+1] == '('):
				counter = counter + 1
		
		elif (i == (length_list - 1)):
			continue		
    		else:
			if ((strings == api_name) and \
			(temp[i - 1] == ';' or (temp[i - 1] == '=')   or  temp[i - 1] == ','  or (temp[i - 1] == '}')) \
			and (temp[i+1] == '(')):
				counter = counter + 1
		i = i + 1

	return counter

"""
simple counter for structure declarations, for a structure declaration like 
sructure , its previous chars should be "struct" ,its after_char should be anything
"""

def simple_api_structure_counter(api_name, token_list):
	i = 0
	counter = 0
	
	length_list = len(token_list)
	temp = token_list
	
	for strings in temp:
		if ((strings == api_name) and (temp[i - 1] == 'struct')):
			counter = counter + 1
		i = i + 1
	return counter
	





"""
Complicated counter for socket API, for a function call like 
function socket call and also structure declare.  Function calls its previous chars should be ";"," = " , "nothing" or 
"}",its after_char should be char "(" . structure declaration its previous should struct.  

input: para@api_funtion_call name lists, @api_structure_declarations, file token list, dictionary of whole api call
output: all different counters based on api names, updated dicionary of whole api call
"""
"""
def api_counter(api_function_calls, api_structure_declarations, file_token, dic_whole_api):
	i = 0
	counter = 0

	length_list = len(file_token)


	#print length_list

	temp = file_token
	for strings in temp:

		
		if (i == 0):
			if (temp[i] == api_name) and (temp[i+1] == '('):
				counter = counter + 1

		elif (i == (length_list - 1)):
			continue
		else:
 			if ((temp[i] == api_name) and \
			(temp[i - 1] == ';' or (temp[i - 1] == '=')   or  temp[i - 1] == ','  or (temp[i - 1] == '}')) \
			and (temp[i+1] == '(')):
			counter = counter + 1
		i = i + 1

	return counter


"""




