import socket
import os
import time
import hashlib
from aesdet import AESDet as PRF
from cryptography.fernet import Fernet
from rake_nltk import Rake
from base64 import b64encode,b64decode
from os import listdir
from os.path import isfile, join
# Implementation of DESSE
# Authors Shailesh Navale, Ayushi Sharma
class Node:
    def __init__(self,searchtoken,counter):
        self.searchtoken = searchtoken
        self.counter = counter

class Client:
    def __init__(self,secpar):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secpar = secpar
        self.superkey = self.keygen(secpar)
        self.filekey = self.ferKeygen()
        self.hashkeywordmap = {}
        self.keywordmap = {}
        self.keywordcount = 0
        self.M = {} # empty map # the map will store the search token and counter Node
        self.filenames = {}
        self.filecounter = 0
        self.connect_to_server()

    def perfXor(self,msg,key):
        val = []
        for char in msg:
            val.append(ord(char)^key)
        return val

    def decXor(self,valuelist,key):
        str =""
        for val in valuelist:
            str+=chr(val^key)
        return str

    def clientsearch(self, w):
        #check if the keyword exist in the map
        if w not in self.M.keys():
            print("Keyword has not been uploaded!!")
            return
        node = self.M[w]
        # generate the token and send it to the server
        tw = self.hashkeywordmap[w]
        self.s.send(str(tw).encode())
        confirm = self.s.recv(1024)
        #print(confirm)
        keywordid = format(self.keywordmap[w],'06d')
        self.s.send(str(keywordid).encode())
        confirm = self.s.recv(1024)
        self.s.send(node.searchtoken.encode())
        #print("Searchtoken:", node.searchtoken)
        confirm = self.s.recv(1024)
        #print(confirm)
        self.s.send(str("req").encode()) # request for size of list
        size = int(self.s.recv(6).decode())
        ID = []
        for i in range(size):
            id = int(self.s.recv(6).decode())
            ID.append(id)
        print("The keyword is present in the files with id:",ID)
        self.s.shutdown(socket.SHUT_RDWR)
        self.s.close()
        self.reconnect()

    def clientupdate(self,ind,w,op):
        # ks, M, ind, w, op
        toprint = {}
        print("---------------------------------------------------")
        print("Inside client update function")
        print("----------------------------------------------------")

        if w not in self.hashkeywordmap.keys():
            print("This is the first occurance of the keyword hence generating token:")
            tw = self.permute(self.superkey,hash(w)) #get the encrypted token
            self.hashkeywordmap[w] = tw
        tw = self.hashkeywordmap[w]
        print("Token for given keyword is:",tw)

        if w not in self.M.keys():
            searchtoken = b64encode(os.urandom(self.secpar)).decode('utf-8')
            #random bytes encoded in b64 for searchtoken
            counter = 0
            node = Node(searchtoken,counter)
            self.M[w] = node
        node = self.M[w]
        print("\nCurrent node for the token is:",end="")
        print(self.M[w])
        searchtoken = node.searchtoken
        print("\nCurrent searchtoken for the keyword is:",searchtoken)
        keynext = self.keygen(self.secpar)
        print("\nGenerating next key for the encryption:",keynext)
        nextsearchtoken = self.permute(keynext,searchtoken).decode()
        print("\nGenerating next search token by permutation of previous:",nextsearchtoken)
        tmp = self.permuteInv(keynext,nextsearchtoken).decode()
        print("\nTesting the decryption of the searchtoken:",tmp)
        self.M[w] = Node(nextsearchtoken,node.counter+1)
        print("\nKeyword is updated on client end:",end="")
        print(self.M[w])
        strkeynext = b64encode(keynext).decode('utf-8') #base 64 encoding is necessary
        concatedstr = str(ind)+","+str(op)+","+strkeynext+","+str(node.counter)
        print("\nconcated string info:",concatedstr)

        oraclekey = self.randomoracle(str(tw)+","+str(nextsearchtoken))
        print("Oracle key computed:",oraclekey)
        #print("next search token:",nextsearchtoken)
        mask = self.perfXor(concatedstr,oraclekey)
        print("Mask computed :",mask)
        print("Decrypting mask for checking:",end="")
        print(self.decXor(mask,oraclekey))
        #print("Sending mask to the server for length:",end="")
        #print(len(mask))
        self.s.send(str(format(len(mask),'06d')).encode())
        for val in mask:
            self.s.send(str(format(val,'06d')).encode())
            #print(val,end=",")
        #send the keyword number to server
        if w not in self.keywordmap.keys():
            self.keywordmap[w] = self.keywordcount
            self.keywordcount +=1
        self.s.send(format(self.keywordmap[w],'06d').encode())
        confirm = self.s.recv(3)
        #print("confirmation",confirm)
        self.s.shutdown(socket.SHUT_RDWR)
        self.s.close()
        self.reconnect()
        print("Exiting client update function")
        print("*******************************************")

    def ferKeygen(self):
        key = Fernet.generate_key()
        return key

    def encryptFile(self,plainfilename, encfilename, key):
        fernet = Fernet(key)
        with open(plainfilename, 'rb') as file:
            original = file.read()
        encrypted = fernet.encrypt(original)
        with open(encfilename, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)

    def decryptFile(self,encfilename, plainfilename, key):
        fernet = Fernet(key)
        with open(encfilename, 'rb') as enc_file:
            encrypted = enc_file.read()
        decrypted = fernet.decrypt(encrypted)
        with open(plainfilename, 'wb') as dec_file:
            dec_file.write(decrypted)

    def getKeywords(self,filename):
        # this function uses the rake library for extraction of the keywords
        # rake has a good performance and easy to use
        # spacy, yake, rake-nltk  are some of the libraries
        rake_nltk_var = Rake()
        file = open(filename, "r")
        text = file.read()
        rake_nltk_var.extract_keywords_from_text(text)
        keyword_extracted = rake_nltk_var.get_ranked_phrases()
        return keyword_extracted

    def randomoracle(self,str):
        # random oracle is a true random hash function
        # for this implementation we are using hash we will be able to change it in future
        # as per wikipedia A system that is proven secure when every hash function is replaced by a random oracle is described as being secure in the random oracle model
        result = hashlib.sha1(str.encode())
        return int(result.hexdigest(), 16) % (2**10)

    def keygen(self,secpar):
        secpar=32
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

    def connect_to_server(self):
        self.target_ip = input('Enter ip --> ')
        self.target_port = input('Enter port --> ')
        self.s.connect((self.target_ip, int(self.target_port)))
        self.main()

    def reconnect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.target_ip, int(self.target_port)))

    def recvFile(self,file_name):
        self.s.send(file_name.encode())
        #check if file exist on the server end
        confirmation = self.s.recv(1024)
        if confirmation.decode() == "file-doesn't-exist":
            print("File doesn't exist on server.")
            self.s.shutdown(socket.SHUT_RDWR)
            self.s.close()
            self.reconnect()
        else:
            write_name = file_name
            if os.path.exists(write_name):
                os.remove(write_name)
            with open(write_name, 'wb') as file:
                while 1:
                    data = self.s.recv(1024)
                    if not data:
                        break
                    file.write(data)
            print(file_name, 'successfully downloaded.')
            self.s.shutdown(socket.SHUT_RDWR)
            self.s.close()
            self.reconnect()

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

    def perfFileOp(self,filename,op,choicecode):
        # op can be add or del
        keywords = self.getKeywords(filename)
        if filename not in self.filenames.keys():
            self.filenames[filename] = self.filecounter+1
            self.filecounter+=1
        ind = self.filenames[filename]
        for word in keywords:
            self.s.send(choicecode.encode())
            print("Updating keyword:", word)
            self.clientupdate(ind, word, op)

    def folderOp(self,folderpath,op,choicecode):
        files = os.listdir(folderpath)
        for file in files:
            file = folderpath+"/"+file
            self.perfFileOp(file,op,choicecode)
            os.system('cls' if os.name == 'nt' else 'clear')

    def showAllKeywords(self):
        print("All Keywords uploaded are as follows:")
        print(self.keywordmap.keys())

    def main(self):
        while 1:
            # 1 - receive the file
            choice = input('Enter your choice:')
            self.s.send(choice.encode())
            if choice == '1':
                file_name = input('Enter file name on server:')
                self.recvFile(file_name)
            elif choice=='2':
                file_name=input('Enter the filename you want to upload:')
                self.s.send(file_name.encode())
                self.sendFile(self.s, file_name)
                self.reconnect()
            elif choice=='3':
                ind = input('please enter the index:')
                op = input('please enter the operation:')
                word = input('please enter the keyword:')
                self.clientupdate(ind,word,op)
                print("keyword is updated to the server!!")
            elif choice=='4':
                w = input("Enter the keyword to search:")
                self.clientsearch(w)
            elif choice=='5':
                filename = input("Enter the filename:")
            elif choice=='6':
                filename = input('please enter filename:')
                op = input('please enter operation:')
                self.s.shutdown(socket.SHUT_RDWR)
                self.s.close()
                self.reconnect()
                self.perfFileOp(filename,op,'3')
            elif choice=='7':
                self.showAllKeywords()
                self.s.shutdown(socket.SHUT_RDWR)
                self.s.close()
                self.reconnect()
            elif choice=='8':
                self.s.shutdown(socket.SHUT_RDWR)
                self.s.close()
                self.reconnect()
                path = input("please enter the path to upload keywords:")
                op = input("please enter the operation:")
                self.folderOp(path,op,'3')
            else:
                print('wrong choice entered')
                self.s.shutdown(socket.SHUT_RDWR)
                self.s.close()
                self.reconnect()

client = Client(128)