#!/usr/bin/python
import sys, re


#This is just an example about how to do regular express 
for line in sys.stdin.readlines():
	#if line == '\n':
	if re.match("^( |\t)*\n$", line):
		print "STRING \"%s\" matches."%line
		continue
	print line



