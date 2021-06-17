import random
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

class FSSENode:
    def __init__(self,id,key):
        self.id = id
        self.key = key

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
        self.ffsekeywords = {}
        self.ffseblockids = []
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
        if w not in self.ffsekeywords.keys():
            print("Keyword not uploaded")
            self.s.shutdown(socket.SHUT_RDWR)
            self.s.close()
            self.reconnect()
            return
        node = self.ffsekeywords[w]
        self.s.send(format(node.id,'06d').encode())
        cfm = self.s.recv(3)
        self.s.send(node.key.encode())
        cfm = self.s.recv(3)
        self.s.send(str("req").encode())
        size = int(self.s.recv(6).decode())
        output = []
        for i in range(size):
            ind = int(self.s.recv(6).decode())
            output.append(ind)
        print("Keyword is present in files with index in :",output)
        self.s.shutdown(socket.SHUT_RDWR)
        self.s.close()
        self.reconnect()

    def clientupdate(self,ind,w,op):
        # ks, M, ind, w, op
        print("---------------------------------------------------")
        print("Inside client update function")
        print("----------------------------------------------------")
        if w not in self.ffsekeywords.keys():
            # generate a new empty block for the keywords
            print("Keyword is not present in current list")
            num = 0
            while True:
                num = random.randint(1,999999)
                if num not in self.ffseblockids:
                    self.ffseblockids.append(num)
                    break
            r = b64encode(self.keygen(self.secpar)).decode('utf-8')
            key = "firstnode"
            node = FSSENode(num,key)
            self.ffsekeywords[w] = node
        node = self.ffsekeywords[w]
        r = b64encode(self.keygen(self.secpar)).decode('utf-8')
        keynext = self.permute(self.superkey,r).decode()
        idnext = 0
        while True:
            num = random.randint(0, 999999)
            if num not in self.ffseblockids:
                idnext = num
                break
        # generate oracle key using keynext, idnext

        oraclekey = self.randomoracle(keynext+","+str(idnext))
        print("Oracle key is :", oraclekey)
        concatedstr = str(ind)+","+str(op)+","+node.key+","+str(node.id)
        print("Concated string is:",concatedstr)
        mask = self.perfXor(concatedstr,oraclekey)
        print("Mask generated:",mask)
        self.s.send(str(format(len(mask), '06d')).encode())
        for val in mask:
            self.s.send(str(format(val,'06d')).encode())
        self.s.send(format(idnext, '06d').encode())
        print("Blockid:",idnext)
        self.ffsekeywords[w].id = idnext
        self.ffsekeywords[w].key = keynext
        confirm = self.s.recv(3)
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
        start_time = time.time()
        for file in files:
            file = folderpath+"/"+file
            self.perfFileOp(file,op,choicecode)
            os.system('cls' if os.name == 'nt' else 'clear')
        print("---------------------------------------------------")
        print("--- %s seconds ---" % (time.time() - start_time))
        print("number of keywords:", len(self.ffsekeywords.keys()))
        print("----------------------------------------------------")

    def showAllKeywords(self):
        print("All Keywords uploaded are as follows:")
        print(self.ffsekeywords.keys())

    def game1(self,choice):
        keywords = self.ffsekeywords.keys()
        start_time = time.time()
        for w in keywords:
            self.s.send(choice.encode())
            self.clientsearch(w)
        print("---------------------------------------------------")
        print("--- %s seconds ---" % (time.time() - start_time))
        print("number of keywords:", len(self.ffsekeywords.keys()))
        print("----------------------------------------------------")

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
            elif choice=='9':
                self.s.shutdown(socket.SHUT_RDWR)
                self.s.close()
                self.reconnect()
                self.game1('4')
            else:
                print('wrong choice entered')
                self.s.shutdown(socket.SHUT_RDWR)
                self.s.close()
                self.reconnect()

client = Client(128)