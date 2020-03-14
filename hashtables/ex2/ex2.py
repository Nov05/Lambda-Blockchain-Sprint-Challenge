#  Hint:  You may not need all of these.  Remove the unused functions.
from hashtables import (HashTable,
                        hash_table_insert,
                        hash_table_remove,
                        hash_table_retrieve,
                        hash_table_resize)


class Ticket:
    def __init__(self, source, destination):
        self.source = source
        self.destination = destination


def reconstruct_trip(tickets, length):
    hashtable = HashTable(length)
    route = [None] * length

    """
    YOUR CODE HERE
    """
    for t in tickets:
        hash_table_insert(hashtable, t.destination, t.source) # hash table, key, value
        if t.destination=='NONE':
            route[-1] = t.source

    for i in range(length-1, 1, -1):
        route[i-1] = hash_table_retrieve(hashtable, route[i])

    return route[1:]
