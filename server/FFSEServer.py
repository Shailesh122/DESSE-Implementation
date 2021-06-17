import socket
import threading
import os, time
from aesdet import AESDet as PRF
import hashlib
from base64 import b64encode,b64decode

class BSTNode:
    def __init__(self, nodevalue,mask):
        self.left = None
        self.right = None
        self.id = nodevalue
        self.mask = mask

class BST:
    def __init__(self):
        self.root = None

    def insert(self,nodevalue,mask,root=None,visitedroot=False):
        if visitedroot==False:
            root = self.root #handle default argument
        if root is None:
            self.root = BSTNode(nodevalue,mask)
            return self.root
        else:
            if root.id == nodevalue:
                return root
            elif root.id < nodevalue:
                root.right = self.insert(nodevalue,mask,root.right,True)
            else:
                root.left = self.insert(nodevalue,mask,root.left,True)
        if visitedroot==False:
            self.root = root
        return root

    def search(self, nodevalue,root=None,visitedroot=False):
        # Base Cases: root is null or nodevalue is present at root
        if visitedroot==False:
            root = self.root #handle default argument
        if root is None or root.id == nodevalue:
            return root

        # nodevalue is greater than root's nodevalue
        if root.id < nodevalue:
            return self.search(nodevalue,root.right,True)

        # nodevalue is smaller than root's nodevalue
        return self.search(nodevalue, root.left,True)

    def inorder(self,root=None,visitedroot=False):
        if visitedroot==False:
            root = self.root #handle default argument
        if root:
            self.inorder(root.left,True)
            print(root.id)
            self.inorder(root.right,True)

class Server:
    def __init__(self):
        self.T = {}  # empty map
        self.bst = BST()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.accept_connections()

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
        print("---------------------------------------")
        print("Inside server receive mask function")
        print("---------------------------------------")
        mask = []
        strmask = ""
        size = int(c.recv(6).decode())
        print("size of the mask is :",end="")
        print(size)
        for i in range(size):
            val = c.recv(6).decode()
            mask.append(int(val))
            #print("received value:",val)
        print("Mask:", end="")
        print(mask)
        blockid = int(c.recv(6).decode()) # Block id received
        print("Blockid:",blockid)
        self.bst.insert(blockid,mask)
        c.send(str('cfm').encode())
        c.shutdown(socket.SHUT_RDWR)
        c.close()
        print("*****************************************")

    def serversearch(self,c):
        print("----------------------------------------------------")
        print("Inside the server search function")
        print("------------------------------------------------------")
        #start_time = time.time()
        id = int(c.recv(6).decode())
        c.send(str("cfm").encode())
        key = c.recv(1024).decode()
        c.send(str("cfm").encode()) # send confirmation to client
        while True:
            print("key for oracle:",key)
            print("id for oracle:",id)
            oraclekey = self.randomoracle(key+","+str(id))
            print("Oracle key is :",oraclekey)
            node = self.bst.search(id)
            if node is None:
                break
            result = self.decXor(node.mask, oraclekey)
            print("Decrypting result:",result)
            resultlist = result.split(',')
            if len(resultlist)<4:
                print("Length of result list is less than 4")
                break
            elif len(resultlist)==4:
                key = resultlist[2]
            else:
                for i in range(2,len(resultlist)-2):
                    key += (resultlist[i]+",")
                key = key[:-1]
            ind = resultlist[0]
            op = resultlist[1]
            id = int(resultlist[len(resultlist)-1])
            if key=="firstnode":
                break
            print("next key:",key)
            print("next id:",id)
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
            c.shutdown(socket.SHUT_RDWR)
            c.close()


server = Server()