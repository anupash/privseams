import os, sys
import apsw
import shutil
from conf_reader import ConfReader
#from pysqlite2 import dbapi2 as sqlite

#reference: http://www.initd.org/pub/software/pysqlite/apsw/3.3.13-r1/apsw.html


###
### Check we have the expected version of apsw and sqlite
###

class dbHandle:

	def __init__(self):

		print "Using APSW file",apsw.__file__     # from the extension module
		print "APSW version",apsw.apswversion()  # from the extension module
		print "SQLite version",apsw.sqlitelibversion()  # from the sqlite library code



###
### Opening/creating database, initialize database
###
		self.db_path = os.path.join(os.environ['PWD'],'db')
		self.confReader = ConfReader('sockets_analysis.conf')

		self.functions = self.confReader.getItems('functions')
		self.structures = self.confReader.getItems('structures')
		
		function_temp = ""
		
		structure_temp = ""

	
		
		for function in self.functions:
			function_temp = function_temp + function[0] + " int,"

		i = 0
		len_item = len(self.structures) # length of items 
		for structure in self.structures:
			if i < len_item - 1:
				structure_temp = structure_temp + structure[0] + " int,"
			else:
				structure_temp = structure_temp + structure[0] + " int"

			i = i + 1
		
		creat_table = "CREATE TABLE socket_statistic (name varchar PRIMARY KEY, " + function_temp  + structure_temp + ")"

		print creat_table		
		
		

		if os.path.exists(self.db_path): 
			print "delete the exsting", self.db_path
			shutil.rmtree(self.db_path) #Removes directories recursively
			#pass
		
		
		print "create the db directory"
		os.mkdir('db')
		database_file =  os.path.join(self.db_path, 'socket_analysis_data_sos.db')
		self.connection=apsw.Connection(database_file)
		self.cursor=self.connection.cursor()
		self.cursor.execute(creat_table)		
		
		#Create table



###
### Cleanup
###


#work only with apsw version 3.3.13-r1 
# We must close connections
#	def close(self):
#		self.connection.close(True)  # force it since we want to exit


#insert analysis data based on each application

	def insert_analysis_data(self): 
		pass

testing = dbHandle()

#testing.close()

###
### simple statement
###

#cursor.execute("create table foo(x,y,z)")

###
### multiple statements
###



