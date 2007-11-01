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

	def __init__(self, func_list, struc_list, apps_list):

		print "Using APSW file",apsw.__file__     # from the extension module
		print "APSW version",apsw.apswversion()  # from the extension module
		print "SQLite version",apsw.sqlitelibversion()  # from the sqlite library code



###
### Opening/creating database, initialize database
###             
		self.apsw_version = apsw.apswversion()
		self.release_number = self.apsw_version[4:6]
		
		self.db_path = os.path.join(os.environ['PWD'],'db')
		#self.confReader = ConfReader('sockets_analysis.conf')

		#self.functions = self.confReader.getItems('functions')
		#self.structures = self.confReader.getItems('structures')
		
		self.functions = func_list
		self.structures = struc_list
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
	def close(self):
		
		try:
			release_number = int(self.release_number)		
		except:
			return 
		
		if release_number >= 13 : # check the version number
			self.connection.close()  # force it since we want to exit


#insert analysis data based on each application.
#SQL insert syntax:INSERT INTO table_name (column1, column2,...) VALUES (value1, value2,....)
	def insert_analysis_data(self, app_name, apps_api_counter_dic): 
		#for items in apps_api_counter_dic:
		apps_api_counter_dic.update({'name':app_name})
		self.cursor.execute("insert into socket_statistic(:name, :connect, :recvfrom, :socket, :in_addr, :sockaddr, :bind, :sockaddr_in, :sockaddr_in6, :accept, :write, :send, :sendto, :sockadd_storage, :close, :recv, :in6_addr, :listen)", apps_api_counter_dic)
		




###
### simple statement
###

#cursor.execute("create table foo(x,y,z)")

###
### multiple statements
###



