#include "list.h"


DList * alloc_list (void)  {	
	DList * list = (struct DList *) malloc (sizeof(DList));
	list->data = NULL;
	list->next = NULL;
	list->prev = NULL;
	
	return list;	
}

DList * free_list_chain (DList * list) {
	if (!list) {
		return;
	}
	
	DList * tmp = NULL;
	
	if (list->prev) {
		tmp = list->prev;
		tmp->next = list->next;
		list->next = NULL;
		list->prev = NULL;
		free (list->data);
		list->data = NULL;
		free (list);	
	}
	
	return tmp;
}

void free_list (DList * list) {
	
	DList * head = list_first (list);
	
	DList * tmp = NULL;
	
	while (head) {
		tmp = head;
		head = tmp->next;
		tmp->prev = NULL;
		tmp->next = NULL;
		free (tmp->data);
		tmp->data = NULL;
		free (tmp);		
	}	
}

DList * list_first (DList * list) {
	if (list) {
		while (list->prev) {
			list = list->prev;
    	}
    }
  
  	return list;	
}

DList * list_last (DList * list) {
	if (list) {
		while (list->next) {
			list = list->next;
    	}
    }
    
  	return list;	
}

unsigned int list_length (DList * list) {
	unsigned int length = 0;
	list = list_first (list);
	if (list) {
		while (list->next) {
			length++;
		}	
	}
	return length;	
}

DList * append_to_list (DList * list,
					 void *  data) {
	if (list) {	
		list = list_last (list);
		DList * tmp = alloc_list ();
		tmp->data = data;
		tmp->prev = list;
		list->next = tmp;
		list = tmp;
	} else {
		list = alloc_list ();
		list->data = data;
	}
	return list;	 	
}

DList * prepend_to_list (DList * list,
					 	 void *  data) {
	if (list) {
		list = list_first (list);
		DList * tmp = alloc_list ();
		tmp->data = data;
		tmp->next = list;
		list->prev = tmp;
		list = tmp;
	}
	return list;					 	 	
} 

DList * remove_from_list (DList * list,
               				    const void * data) {
	DList * tmp;
	tmp = list;
	
	while (tmp) {
		if (tmp->data != data) {  	
        	tmp = tmp->next;
		} else {
			if (tmp->prev) {
				tmp->prev->next = tmp->next;
			} 
			if (tmp->next) {
				tmp->next->prev = tmp->prev;
			}	
          
			if (list == tmp) {
				list = list->next;
			}
		
			free_list_chain (tmp);
   	       
			break;
		}
	}
	return list;
}

DList * 
remove_link_dlist (DList * list,
				   DList * link) {
	if (link) {
		if ( link->prev) {
			link->prev->next = link->next;
		}
		if (link->next) {
			link->next->prev = link->prev;
		}
      	if (link == list) {
			list = list->next;
      	}
      
		link->next = NULL;
		link->prev = NULL;
	}
	return list;					  	
}

DList* find_in_dlist (DList * list, 
	   			      void * data) {
	while (list) {
		if (list->data == data) {
			break;
		}
      	list = list->next;
	}
	return list;
}

