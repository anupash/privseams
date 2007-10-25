# string_token.py file is for handling all string related functionality
#!/usr/bin/python
import shlex



"""
Take the whole string as a parameter, return a object of Token
"""
def string_lexical(string_needs_parse):
	lexer = shlex.shlex(string_needs_parse)
	return lexer



"""
simple counter for socket API, for a function call like 
function socket call, its previous chars should be ";"," = " , "nothing" or 
"}",its after_char should be char "(" 
"""
def simple_api_counter(api_name, whole_lexer):
	previous_chars = ""
	after_chars = ""


	for token in whole_lexer:

    
