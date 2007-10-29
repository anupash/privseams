import os, sys
import apsw
import shutil
#from pysqlite2 import dbapi2 as sqlite

#reference: http://www.initd.org/pub/software/pysqlite/apsw/3.3.13-r1/apsw.html


###
### Check we have the expected version of apsw and sqlite
###

print "Using APSW file",apsw.__file__     # from the extension module
print "APSW version",apsw.apswversion()  # from the extension module
print "SQLite version",apsw.sqlitelibversion()  # from the sqlite library code



###
### Opening/creating database, initialize database
###

db_path = os.path.join(os.environ['PWD'],'db')


if os.path.exists(db_path): 
	print "delete the exsting", db_path
	shutil.rmtree(db_path) #Removes directories recursively


print "create the db directory"
os.mkdir('db')
database_file =  os.path.join(db_path, 'socket_analysis_data_sos.db')
connection=apsw.Connection(database_file)
cursor=connection.cursor()

###
### Cleanup
###


#work only with apsw version 3.3.13-r1 
# We must close connections
#connection.close(True)  # force it since we want to exit



###
### simple statement
###

#cursor.execute("create table foo(x,y,z)")

###
### multiple statements
###



