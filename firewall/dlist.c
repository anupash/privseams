/**
 * @file firewall/dlist.c
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
 * Linked list implementation operating based on pointers. It is
 * recommended to use lib/core/list.h implementation which supports
 * searching based on indexes (rather than pointers) can later also be
 * easily changed into a hashtable if needed.
 *
 * @brief Simple linked list implementation
 *
 **/

#include "dlist.h"

/**
 * Initialize and allocate memory for a new linked list.
 *
 * @return the linked list (caller frees)
 */
DList * alloc_list (void)  {	
	DList * list = (DList *) malloc (sizeof(DList));
	list->data = NULL;
	list->next = NULL;
	list->prev = NULL;
	
	return list;	
}

/**
 * Remove a link from the list
 *
 * @param the link to be removed
 * @return a pointer to the original list
 **/
DList * free_list_chain (DList * list) {
	DList * tmp = NULL;
	
	if (!list) {
		return NULL;
	}
	
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

/**
 * Deallocate the memory allocated for the entire linked list.
 * If the linked list items contain pointer to other allocated
 * items, the caller must free them beforehand!
 *
 * @todo (what's the difference to the previous function?)
 *
 * @param list the list to be deallocated
 * @return a pointer to the original list
 **/
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

/**
 * get a pointer to the previous list item
 *
 * @param list a pointer to the list
 * @return a pointer to the previous list item
 **/
DList * list_first (DList * list) {
	if (list) {
		while (list->prev) {
			list = list->prev;
    	}
    }
  
  	return list;	
}

/**
 * get a pointer to the next list item
 *
 * @param list a pointer to the list
 * @return a pointer to the next list item
 **/
DList * list_last (DList * list) {
	if (list) {
		while (list->next) {
			list = list->next;
    	}
    }
    
  	return list;	
}

/**
 * calculate the number of list items
 *
 * @param list the linked list
 * @return the number of items on the linked list
 **/
unsigned int list_length (DList * list) {
	unsigned int length = 0;
	list = list_first (list);
	if (list) {
		while (list->next) {
			length++;
			list = list->next;
		}	
	}
	return length;	
}

/**
 * append a new element to the linked list
 *
 * @param list the linked list
 * @param data the new item to be appended
 * @return a pointer to the new item in the linked list
 **/
DList * append_to_list (DList * list,
			void *  data) {
  DList *new_list;
  DList *last;
  
  new_list = alloc_list ();
  new_list->data = data;
  new_list->next = NULL;
  
  if (list)
    {
      last = list_last (list);
      last->next = new_list;
      new_list->prev = last;
      
	  HIP_DEBUG("List is not empty. Length %d\n", list_length(list)); 
      return list;
    }
  else
    {
      new_list->prev = NULL;
      HIP_DEBUG("List is empty inserting first node\n");
      return new_list;
    }	 	
}

/**
 * remove an element from the linked list by searching
 *
 * @param list the linked list
 * @param data the element to be removed
 * @return a pointer to the linked list
 **/
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

/**
 * remove a given link from the linked list
 *
 * @param the linked list
 * @return link the link to be removed
 **/
DList * remove_link_dlist (DList * list,
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

/**
 * find an element in the linked list
 *
 * @param list the linked list
 * @param data the element to find
 * @return the element in the linked list
 **/
DList *find_in_dlist (DList * list, 
		      void * data) {
	while (list) {
		if (list->data == data) {
			break;
		}
      	list = list->next;
	}
	return list;
}
