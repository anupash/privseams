#! /usr/bin/python
################################################################################
#
# Script to clean the grep outputs and then reformats it to a dot language 
# representation of the graph them for graphviz
#
# Also prints the macro declared includes but ignores them in the graph
# 
# Author: Samu Varjonen
#
# NOTE: Call graphviz_script.sh not this!!
# NOTE: see man grapviz for more information
#
################################################################################

def print_header():
    print >>f, "digraph G"
    print >>f, "{"
    print >>f, "    edge [len=20];"
    print >>f, " "
    return 

def print_end():
    print >>f, "}"
    return

def clean_and_store( line ):
    global countodds

    # find where is included
    # and what is included
    slash = line.find("/")
    comma = line.find(":")
    where = line[slash + 1 :comma]
    quotation = line.find('"')
    lthan = line.find("<")
    doth = line.find(".h", comma)
   
    if quotation > 0:
        marker = quotation
    elif lthan > 0:
        marker = lthan
    else:
        countodds = countodds + 1
        print line
        return    
    what = line[marker + 1:doth + 2]

    #remove all the illegal characters dot
    where = where.replace(".","_")
    what = what.replace(".","_")
    where = where.replace("/","_")
    what = what.replace("/","_")
    where = where.replace("-","_")
    what = what.replace("-","_")

    print >>f, "   " + where + ' -> ' + what + ";" 
    return

f = open('out.txt','w')
countodds = 0
print_header()
for line in open('/tmp/grep_results.txt','r'):
    clean_and_store(line)
print_end()
print "Number of macro defined includes skipped", countodds, "printed them above"
