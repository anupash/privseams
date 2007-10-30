from conf_reader import ConfReader
from search_engine import SearchEngine
from file_input import *
from directory_working import *

#reader = ConfReader('sockets_API.conf')
reader = ConfReader('sockets_analysis.conf')

#reader.print_test()

#print reader.getValue('functions', 'socket')
#print reader.getItems('functions')
#print reader.getItems('structures')

functions = reader.getItems('functions')
structures = reader.getItems('structures')

#all = reader.getItems('functions') + reader.getItems('structures')
all = functions + structures


reader.saveItemsDic('functions')
reader.saveItemsDic('structures')
dic = reader.getDicContainer()
#print dic['socket']
#print dic['bind']

print all

#search_engine = SearchEngine(all)
#search_engine.update_function_call_counters('socket', 4)
#search_engine.print_counts()

#string_temp = readFile('test.c')

#print "----------------------------------------"

#api_counter(functions, structures, string_temp, search_engine)
#search_engine.print_counts()


#string_temp = readFile('/home/twan/hipl--beet--2.6/test/sockets_API_statistics/applications/MPlayer-1.0rc2/libmpcodecs/vf_2xsai.c')
#print "-------------------------------------"

#temp = string_lexical(string_temp) 
#print simple_api_function_counter('sendto', temp)

#api_counter(functions, structures, string_temp, search_engine)

#walk_tree_print_c_files(os.path.join(os.environ['PWD'],'applications'), functions, structures,search_engine)

#search_engine.print_counts()


