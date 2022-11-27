#Server_AS_TGS

import socket
import pyDes as pydes
import time
import client
import server 

#message objects
class Packet:
    def __init__(self, content, TS, ID_C, ID_V, ID_TGS, lifetime2, lifetime4):
        self.content = content
        self.TS = TS
        self.ID_C = ID_C
        self.ID_V = ID_V
        self.ID_TGS = ID_TGS
        self.lifetime2 = lifetime2
        self.lifetime4 = lifetime4


def getDESKeyFromFile(filename):
    DES_key = None
    with open(filename, "r") as key_file:
        DES_key = key_file.readline().strip("\r\n")

    print("The shared DES Key is: " + DES_key)
    return DES_key

def startAsTgsServer(AS_key, TGS_key, V_key):
    socket_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('127.0.1', 10000)

    while True:
        #AS handler
        socket_.bind(server_address)
        socket_.listen()
        print("Waiting for connection...")
        connection, client_address = socket_.accept()
        print("Connection has been made.")

        received = socket_.recv(1024000000)
        AS_TS_2 = time.time()
        if(received.TS < AS_TS_2 - 60000):
            print("Invalid (timeout)")
            return
        #decrypting AS_key encryption
        key = pydes.des("DESCRYPT", pydes.CBC, AS_key, pad=None, padmode=pydes.PAD_PKCS5)
        message = key.decrypt(received.content, padmode=pydes.PAD_PKCS5)
        print("Message received at AS: " + repr(message))

        #encrypt with TGS_key encryption
        key = pydes.des("DESCRYPT", pydes.CBC, TGS_key, pad=None, padmode=pydes.PAD_PKCS5)
        message = key.encrypt(message)

        #create packet to return to C
        packet_AS_C = Packet(message, AS_TS_2, None, None, received.ID_TGS, 60000, None)

        #send packet to C
        connection.send(packet_AS_C)

        ####################################################################
        #TGS handler
        received = socket_.recv(1024000000)
        TGS_TS_2 = time.time()
        if(received.TS < TGS_TS_2 - 60000):
            print("Invalid (timeout)")
            return
        #decrypting AS_key encryption
        key = pydes.des("DESCRYPT", pydes.CBC, TGS_key, pad=None, padmode=pydes.PAD_PKCS5)
        message = key.decrypt(received.content, padmode=pydes.PAD_PKCS5)
        print("Message received at TGS: " + repr(message))

        #encrypt with TGS_key encryption
        key = pydes.des("DESCRYPT", pydes.CBC, V_key, pad=None, padmode=pydes.PAD_PKCS5)
        message = key.encrypt(message)

        #create packet to return to C
        packet_TGS_C = Packet(message, TGS_TS_2, received.ID_C, received.ID_V, None, None, 86400000)

        #send packet to C
        connection.send(packet_TGS_C)
    
def main():
    AS_key = getDESKeyFromFile("keys/K_AS.txt")
    TGS_key = getDESKeyFromFile("keys/K_TGS.txt")
    V_key = getDESKeyFromFile("keys/K_V.txt")

    startAsTgsServer(AS_key, TGS_key, V_key)
    return

# This snippet of code verifies that this file was called through the command
# line and not through another python file. (reduces unnecessary errors)
if __name__ == "__main__":
    main()
