#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "my402list.h"

int My402ListEmpty(My402List *list)
{
	if(((list->anchor.prev)==(&list->anchor)))
	{
	 return 1;
	}
	else
	{
	 return 0;
	}
}


My402ListElem *My402ListFirst(My402List* list)
{
	if(My402ListEmpty(list)==1)
	{
	printf("list is empty");
	return 0;
	}
	else
	{
	return list->anchor.next;
	}
}
My402ListElem *My402ListLast(My402List* list)
{
	if(My402ListEmpty(list)==1)
	{
	printf("list is empty");
	return 0;
	}
	else
	{
	return list->anchor.prev;
	}
}
	
My402ListElem *My402ListNext(My402List* list, My402ListElem* elem)
{
	if(elem->next==&list->anchor)
	{
		return 0;
	}
	else
	{
	return elem->next;
	}
}
My402ListElem *My402ListPrev(My402List* list, My402ListElem* elem)
{
	if(list->anchor.next== elem)
	{
	return 0;
	}
	else
	{
	return elem->prev;
	}
}
	
My402ListElem *My402ListFind(My402List* list, void* obje )
{
	My402ListElem *temp;
	if(My402ListEmpty(list)==1)
	{
	printf("list is empty");
	return 0;
	}
	else
	{	temp=list->anchor.next;
		do
		{
			if(temp->obj==obje)
			{
			return temp;
			}
			else
			{
			temp=temp->next;
			}
		}while(&list->anchor != temp);//changed from temp.next to temp
		printf("Object not found");
		return 0;
		}
}
	
int  My402ListLength(My402List* list)
{	
		return list->num_members;
}

int  My402ListAppend(My402List* list, void* obje)
{
	My402ListElem *temp,*temp_elem;
	if(My402ListEmpty(list)==1)
	{
	temp_elem=(My402ListElem *)malloc(sizeof(My402ListElem));
	temp_elem->obj=obje;
	list->anchor.prev=temp_elem;
	list->anchor.next=temp_elem;
	temp_elem->next=&list->anchor;
	temp_elem->prev=&list->anchor;
	list->num_members+=1;
	}
	else
	{
	temp=list->anchor.prev;
	temp_elem=(My402ListElem *)malloc(sizeof(My402ListElem));
	temp_elem->obj=obje;
	
	temp_elem->prev=temp;
	temp_elem->next=&list->anchor;
	temp->next=temp_elem;
	list->anchor.prev=temp_elem;
	list->num_members+=1;
	//increment num_members
	}
	return 1;
}
	
int  My402ListPrepend(My402List* list, void* obje)
{
	
	My402ListElem *temp,*temp_elem;
	if(My402ListEmpty(list)==1)
	{
	temp_elem=(My402ListElem *)malloc(sizeof(My402ListElem));
	temp_elem->obj=obje;
	
	list->anchor.prev=temp_elem;
	list->anchor.next=temp_elem;
	temp_elem->next=&list->anchor;
	temp_elem->prev=&list->anchor;
	list->num_members+=1;
	}
	else
	{
	temp=list->anchor.next;
	temp_elem=(My402ListElem *)malloc(sizeof(My402ListElem));
	temp_elem->obj=obje;
	temp_elem->next=temp;
	temp_elem->prev=&list->anchor;
	temp->prev=temp_elem;
	list->anchor.next=temp_elem;
	list->num_members+=1;
	}
	return 1;
}


void My402ListUnlink(My402List* list, My402ListElem* elem)
{
	My402ListElem *tempnex,*temppre;
	if(My402ListEmpty(list)==1)
	{
	printf("list is empty");
	}
	else
	{
	tempnex=elem->next;
	temppre=elem->prev;
	elem->prev->next=tempnex;
	elem->next->prev=temppre;
	list->num_members-=1;
	free(elem);
	}
	return;
}

void My402ListUnlinkAll(My402List* list)
{
	
	while(list->num_members !=0)
	{
	My402ListUnlink(list, list->anchor.next);
	}
	return;
}

int  My402ListInsertAfter(My402List* list, void* obje, My402ListElem* elem)
{
	if(list==NULL)
	{
	//My402ListAppend(list, obj);
	return 0;
	}
	My402ListElem *tempnex,*temppre,*temp;
	temp=( My402ListElem *)malloc(sizeof(My402ListElem));
	
	tempnex=elem->next;
	temppre=elem;
	temp->prev=temppre;
	temp->next=tempnex;
	temp->obj=obje;
	elem->next=temp;
	tempnex->prev=temp;
	
	list->num_members+=1;
	return 1;
}

int  My402ListInsertBefore(My402List* list, void* obje, My402ListElem* elem)
{
	if(list==NULL)
	{
	//My402ListPrepend(list, obj);
	return 0;
	}
	
	My402ListElem *tempnex,*temppre,*temp;
	temp=( My402ListElem *)malloc(sizeof(My402ListElem));
	tempnex=elem;
	temppre=elem->prev;
	temp->prev=temppre;
	temp->next=tempnex;
	temp->obj=obje;
	elem->prev=temp;
	temppre->next=temp;
	list->num_members+=1;
	return 1;
}

int My402ListInit(My402List* list)
{
	list->num_members=0;
	list->anchor.next=&list->anchor;
	list->anchor.prev=&list->anchor;
	return 1;
}

