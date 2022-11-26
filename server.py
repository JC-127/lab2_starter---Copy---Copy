
import socket

from crypto import KeyManager, DES

class Server:
    def __init__(self, addr, port, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.addr, self.port))
        self.s.listen(1)
        self.conn, self.addr = self.s.accept()

    def send(self, msg_bytes: bytes):
        self.conn.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        msg_bytes = self.conn.recv(buffer_size)

        return msg_bytes

    def close(self):
        self.conn.close()


if __name__ == '__main__':
    server = Server('localhost', 9998)
    enc_key = KeyManager.read_key('enc_key.txt')
    mac_key = KeyManager.read_key('mac_key.txt')
    des = DES(enc_key, mac_key)

    #Should print out the HMAC and DES Key for server
    #print("The Key is: ", enc_key )
    #print("The MAC Key is: " , mac_key)

    while True:

        cipher_text = server.recv()
        msg = des.decrypt(cipher_text)
        
        print("Mesage is : ", msg)

        msg = input('> ')
        if msg == 'exit':
            break
        cipher_text, mac = des.encrypt(msg)
        server.send(cipher_text)
        print(mac.hex())
        
    server.close() 
