class LNode:
    # Function to initialise the node object
    def __init__(self, data):
        self.data = data  # Assign data
        self.next = None  # Initialize next as null

# Linked List class contains a Node object
class LinkedList:
    # Function to initialize head
    def __init__(self):
        self.head = None

    def printList(self):
        temp = self.head
        while (temp):
            print(temp.data)
            temp = temp.next

    def getValues(self):
        li = []
        temp = self.head
        while (temp):
            li.append(temp.data)
            temp = temp.next
        return li

    def insert(self, val):
        # inserting the node at the begining
        tmp = LNode(val)
        tmp.next = self.head
        self.head = tmp