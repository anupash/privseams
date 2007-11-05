from conf_reader import ConfReader
from search_engine import SearchEngine
from file_input import *
from directory_walking import *
from fetch_files import fetchNetApps
from database_engine import dbHandle


reader = ConfReader('sockets_analysis.conf')


functions = reader.getItems('functions')
structures = reader.getItems('structures')
applications = reader.getItems('applications')

all_socket_api = functions + structures 

fetchnetapps = fetchNetApps(applications)
fetchnetapps.download_apps()
fetchnetapps.decompress_apps()

dbhandle = dbHandle(functions, structures, applications)


search_engine = SearchEngine(all_socket_api)

#count all socket APIs under applications directory
apps_dir = os.path.join(os.environ['PWD'],'applications')

for name in os.listdir(apps_dir):
	path = os.path.join(apps_dir, name)
	for conf_name in applications:
		if conf_name[0].lower() in name.lower():
			print conf_name[0]
		      	app_name = conf_name[0]
			break
				
	
	if os.path.isdir(path):
   		walk_tree_print_c_files(path, functions, structures, search_engine)
		print "application is ", path
		search_engine.print_counts()
		apps_api_counter_dic = search_engine.get_counts()
		dbhandle.insert_analysis_data(app_name,  apps_api_counter_dic)		

	del search_engine
	search_engine = SearchEngine(all_socket_api)


#walk_tree_print_c_files(apps_dir, functions, structures,search_engine)

#search_engine.print_counts()

dbhandle.close()

