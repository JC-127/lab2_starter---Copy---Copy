
import socket
from crypto import KeyManager, DES


class Client:
    def __init__(self, addr, port, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.addr, self.port))

    def send(self, msg_bytes: bytes):
        self.s.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        msg_bytes = self.s.recv(self.buffer_size)

        return msg_bytes

    def close(self):
        self.s.close()


if __name__ == '__main__':
    client = Client('localhost', 9998)
    enc_key = KeyManager().read_key('enc_key.txt')
    mac_key = KeyManager().read_key('mac_key.txt')
    des = DES(enc_key, mac_key)

    #Should print out the HMAC and DES Key for Client side
    #print("The Key is: ", enc_key)
    #print("The MAC Key is: ", mac_key)

    while True:
                
        msg = input('> ')
        if msg == 'exit':
            break
        cipher_text, mac = des.encrypt(msg)
        client.send(cipher_text)
        #print("MAC from server: ", mac.hex())

        cipher_text = client.recv()
        msg = des.decrypt(cipher_text)


    client.close()
