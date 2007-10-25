
from conf_reader import ConfReader
from search_engine import SearchEngine

#reader = ConfReader('sockets_API.conf')
reader = ConfReader('sockets_analysis.conf')

#reader.print_test()

#print reader.getValue('functions', 'socket')
#print reader.getItems('functions')
#print reader.getItems('structures')

functions = reader.getItems('functions')
structures = reader.getItems('functions')

#all = reader.getItems('functions') + reader.getItems('structures')
all = functions + structures


reader.saveItemsDic('functions')
reader.saveItemsDic('structures')
dic = reader.getDicContainer()
#print dic['socket']
#print dic['bind']

print all

search_engine = SearchEngine(all)
search_engine.update_function_call_counters('socket', 4)
search_engine.print_counts()

