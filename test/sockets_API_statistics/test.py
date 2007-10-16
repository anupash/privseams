
from conf_reader import ConfReader


reader = ConfReader('sockets_API.conf')


#reader.print_test()

#print reader.getValue('functions', 'socket')
#print reader.getItems('functions')
reader.saveItemsToHashTable('functions')
reader.saveItemsToHashTable('structures')
dic = reader.getDicContainer()
print dic['socket']
print dic['bind']
