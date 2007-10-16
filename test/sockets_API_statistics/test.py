
from conf_reader import ConfReader
from search_engine import SearchEngine

reader = ConfReader('sockets_API.conf')


#reader.print_test()

#print reader.getValue('functions', 'socket')
#print reader.getItems('functions')
#print reader.getItems('structures')
all = reader.getItems('functions') + reader.getItems('structures')

reader.saveItemsDic('functions')
reader.saveItemsDic('structures')
dic = reader.getDicContainer()
#print dic['socket']
#print dic['bind']

print all

search_engine = SearchEngine(all)
search_engine.print_counts()

