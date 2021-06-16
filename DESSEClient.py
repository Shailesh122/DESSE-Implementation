import socket

class DESSEServer:
    def __init__(self,port):
        self.port = port
        self.sock = socket.socket()
        self.sock.bind('',port)

    def listen(self):
        self.sock.listen(5)
        print("server is listening to the socket")
        while True:
            conn,addr = self.sock.accept() # accept the connection
            print("received connection from", addr)
            conn.send("Thanks for connecting")
            conn.close()

class DESSEClient:
    def __init__(self,port):
        self.port = port
        self.sock = socket.socket()
        