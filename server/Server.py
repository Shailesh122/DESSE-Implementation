import socket
import threading
import os, time
from aesdet import AESDet as PRF
import hashlib
from base64 import b64encode,b64decode
from cryptography.fernet import Fernet
# Implementation of DESSE
# Authors Shailesh Navale, Ayushi Sharma

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


class Server:
    def __init__(self):
        self.T = {}  # empty map
        self.llistmap = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.accept_connections()

    #def randomoracle(self,str):
        # random oracle is a true random hash function
        # for this implementation we are using hash we will be able to change it in future
        # as per wikipedia A system that is proven secure when every hash function is replaced by a random oracle is described as being secure in the random oracle model
        #return hash(str)%32

    def randomoracle(self,str):
        # random oracle is a true random hash function
        # for this implementation we are using hash we will be able to change it in future
        # as per wikipedia A system that is proven secure when every hash function is replaced by a random oracle is described as being secure in the random oracle model
        result = hashlib.sha1(str.encode())
        return int(result.hexdigest(), 16) % (2**10)

    def decXor(self,valuelist,key):
        str =""
        for val in valuelist:
            str+=chr(val^key)
        return str

    def keygen(self,secpar):
        secpar = 32
        while True:
            key = os.urandom(secpar)
            if ',' not in str(key):
                return key
        return os.urandom(32)

    def permute(self,key, msg):
        F1 = PRF()
        F1.add_to_private_key("key", key)
        val = F1.encrypt(msg)
        return val

    def permuteInv(self,key, cipher):
        F2 = PRF()
        F2.add_to_private_key("key", key)
        dec = F2.decrypt(cipher)
        return dec

    def accept_connections(self):
        ip = socket.gethostbyname(socket.gethostname())
        port = int(input('Enter desired port --> '))
        self.s.bind((ip, port))
        self.s.listen(100)
        print('Running on IP: ' + ip)
        print('Running on port: ' + str(port))
        while 1:
            c, addr = self.s.accept()
            print(c)
            # once the connection is accept a new thread is created which will handle
            # that client
            threading.Thread(target=self.handle_client, args=(c, addr,)).start()

    def sendFile(self,c,data):
        if not os.path.exists(data):
            c.send("file-doesn't-exist".encode())
        else:
            c.send("file-exists".encode())
            print('Sending', data)
            if data != '':
                file = open(data, 'rb')
                data = file.read(1024)
                while data:
                    c.send(data)
                    data = file.read(1024)
                c.shutdown(socket.SHUT_RDWR)
                c.close()

    def recvFileServer(self,c,file_name):
        c.send(file_name.encode())
        #check if file exist on the server end
        confirmation = c.recv(1024)
        if confirmation.decode() == "file-doesn't-exist":
            print("File doesn't exist on server.")
            #c.shutdown(socket.SHUT_RDWR)
            #c.close()
        else:
            write_name = file_name
            if os.path.exists(write_name):
                os.remove(write_name)
            with open(write_name, 'wb') as file:
                while 1:
                    data = c.recv(1024)
                    if not data:
                        break
                    file.write(data)
            print(file_name, 'successfully downloaded.')
            #c.shutdown(socket.SHUT_RDWR)
            #c.close()

    def recvMask(self,c):
        mask = []
        strmask = ""
        size = int(c.recv(6).decode())
        #print("size of the mask is :",end="")
        #print(size)
        for i in range(size):
            val = c.recv(6).decode()
            mask.append(int(val))
            #print("received value:",val)
        #print("Mask:", end="")
        #print(mask)
        keywordid = c.recv(6).decode()
        #print("Keyword id is :",end="")
        #print(keywordid)
        #append the mask to the linked list of this node
        if keywordid not in self.llistmap.keys():
            self.llistmap[keywordid] = LinkedList()
        self.llistmap[keywordid].insert(mask)
        c.send(str('cfm').encode())
        c.shutdown(socket.SHUT_RDWR)
        c.close()

    def serversearch(self,c):
        print("----------------------------------------------------")
        print("Inside the server search function")
        print("------------------------------------------------------")
        #start_time = time.time()
        tw = c.recv(1024).decode()
        ID = []
        Z = []
        #print("Token received: ",tw)
        c.send(str("received token!!").encode())
        keywordid = c.recv(1024).decode()
        #print("Keyword id received:",keywordid)
        c.send(str("received keyword id!!").encode())
        searchtoken = c.recv(1024).decode()
        print("type of searchtoken is :",type(searchtoken))
        c.send(str("received token id!!").encode())
        #print("Search token:",searchtoken)
        if keywordid not in self.llistmap.keys():
            print("keyword not present on server")
            return
        #oraclekey = self.randomoracle(str(tw)+","+str(searchtoken))
        #print("oracle key:",oraclekey)
        masklist = self.llistmap[keywordid].getValues()
        #print(masklist)
        #val = self.decXor(masklist[0], oraclekey)
        # value will contain (index, operation, key, counter)
        for mask in masklist:
            oraclekey = self.randomoracle(str(tw) + "," + str(searchtoken))
            val = self.decXor(mask,oraclekey)
            print(val)
            resultlist = val.split(',')
            print("Result list is: ",resultlist)
            if len(resultlist)==4:
                key = resultlist[2]
            elif len(resultlist)<4:
                print("Result list is less than 4: ",end="")
                print(resultlist)
                break
            else:
                key=""
                for i in range(2,len(resultlist)-2):
                    key += (resultlist[i]+",")
                key = key[:-1]
                #key = key.encode()
            ind = resultlist[0]
            operation = resultlist[1]
            counter = resultlist[len(resultlist) - 1]
            print("\nKey is :",key)
            searchtoken = self.permuteInv(b64decode(key),searchtoken).decode()
            print("\nGenerated search token type:",type(searchtoken))
            print("\nGenerated Search token is :",searchtoken)
            if (int(counter)>0):
                if(operation=='del'):
                    if ((ind not in Z) and (ind not in ID)):
                        Z.append(ind)
                        print("Appended to Z")
                elif(operation=='add'):
                    if ((ind not in Z) and (ind not in ID)):
                        ID.append(ind)
            else:
                if ((ind not in Z) and (ind not in ID)):
                    ID.append(ind)
        print("Keyword is available on files:",ID)
        print("Keyword is deleted from the files:",Z)
        req = c.recv(3).decode()
        c.send(format(len(ID),'06d').encode())
        for id in ID:
            c.send(format(int(id),'06d').encode())
        c.shutdown(socket.SHUT_RDWR)
        c.close()


    def handle_client(self, c, addr):
        print("Waiting for the client input.")
        choice = c.recv(1).decode()
        print("Client requested for operation :",choice)
        if choice=='1':
            # send file to client
            filename = c.recv(1024).decode()
            self.sendFile(c,filename)
        elif choice=='2':
            filename = c.recv(1024).decode()
            #client wants to upload filename to server
            print("receiving file:", filename)
            self.recvFileServer(c,filename)
        elif choice=='3':
            self.recvMask(c)
        elif choice=='4':
            self.serversearch(c)
        else:
            print('choice not valid or choice is not applicable for server')


server = Server()