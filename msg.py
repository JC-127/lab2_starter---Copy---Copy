import time
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def assemble2bytes(*args) -> bytes:
    if len(args) == 0:
        return b""
    buffer = b""
    for arg in args:
        if isinstance(arg, str):
            elem = base64.encodebytes(arg.encode())
        elif isinstance(arg, bytes):
            elem = base64.encodebytes(arg)
        else:
            elem = base64.encodebytes(str(arg).encode())
        
        buffer += elem + b" "
    
    buffer = buffer[:-1]
    return buffer

def disassemble2bytes(buffer: bytes) -> 'list[bytes]':
    elems = buffer.split(b" ")
    elems = [ base64.decodebytes(elem) for elem in elems ]
    return elems

# others
BLOCK_SIZE = 16
AD_c = get_random_bytes(BLOCK_SIZE)

# IDs
ID_c = "CIS3319USERID".encode()
ID_v = "CIS3319SERVERID".encode()
ID_tgs = "CIS3319TGSID".encode()

# Keys
K_c = get_random_bytes(BLOCK_SIZE)
K_tgs = get_random_bytes(BLOCK_SIZE)
K_c_tgs = get_random_bytes(BLOCK_SIZE)
K_c_v = get_random_bytes(BLOCK_SIZE)
K_v = get_random_bytes(BLOCK_SIZE)


# compose msg1, (1) C -> AS
#No Encryption needed
TS1 = int(time.time())
print("TS1: ", TS1)
msg1 = assemble2bytes(ID_c, ID_tgs, TS1)

# compose msg2, (2) AS -> C
# ticket first
print("Received message on AS side: ", msg1)
time.sleep(1) # sleep for 1 sec to get different time stamps 
TS2 = int(time.time())
print("TS2: ", TS2)
lifetime2 = 60

#Ticket TGS
ticket_content = assemble2bytes(K_c_tgs, ID_c, AD_c, ID_tgs, TS2, lifetime2)
E_tgs = AES.new(K_tgs, AES.MODE_ECB)
Ticket_tgs = E_tgs.encrypt(pad(ticket_content, BLOCK_SIZE))

# msg2 which (2) AS -> C
# Encryption needed
# E(K_c[K_c_tgs||ID_tgs||lifetime2||Ticket_tgs])
msg2_content = assemble2bytes(K_c_tgs, ID_tgs, TS2, lifetime2, Ticket_tgs)
E_c = AES.new(K_c, AES.MODE_ECB)
msg2 = E_c.encrypt(pad(msg2_content, BLOCK_SIZE))

# compose msg3, C -> TGS
# msg2 was encrypted, decryption is needed
# decrypt msg2 to get ticket first from TGS
msg2_dec = E_c.decrypt(msg2)
Ticket_tgs_recved = disassemble2bytes(msg2_dec)[4]

# Ticket_tgs_dec = E_tgs.decrypt(Ticket_tgs_recved)
# Authenticator first 
time.sleep(1) # sleep for 1 sec to get different time stamps 
TS3 = int(time.time())

#Authenticator_c
#Assembly of msg3; encryption is not needed 
authenticator_content = assemble2bytes(ID_c, AD_c, TS3)
E_c_tgs = AES.new(K_c_tgs, AES.MODE_ECB)
Authenticator_c = E_c_tgs.encrypt(pad(authenticator_content, BLOCK_SIZE))
msg3 = assemble2bytes(ID_v, Ticket_tgs_recved, Authenticator_c)

# before composing msg 4, check ticket lifetime
Ticket_tgs_recved1 = disassemble2bytes(msg3)[1]
Ticket_tgs_dec = E_tgs.decrypt(Ticket_tgs_recved1)
Ticket_tgs_content = disassemble2bytes(Ticket_tgs_dec)
TS2_recved = int(Ticket_tgs_content[4].decode())
lifetime2_recved = int(Ticket_tgs_content[5].decode())

# check expiration
current_time = time.time()
print("current_time: ", current_time)
print("TS2_recved: ", TS2_recved)
print("lifetime2_recved: ", lifetime2_recved)
assert current_time - TS2_recved <= lifetime2_recved, "Ticket_tgs expired."

##################### Start Working Here ####################################

#compose msg4 (4) TGS -> C
#msg 3 was not encrypted so decryption is not needed
#msg3_dec = E_c_tgs.decrypt(msg3)
Ticket_tgs_content = disassemble2bytes(msg3)[4]

time.sleep(1) # sleep for 1 sec to get different time stamps 
TS4 = int(time.time())

#Ticket_tgs for (4) TGS -> C
#Encryption needed for msg4
#E(K_tgs,[K_c_tgs||ID_c||AD_c||ID_tgs||TS2||Lifetime2])
ticket_content_tgs_c = assemble2bytes(K_c_tgs, ID_c, AD_c, ID_tgs, TS2, lifetime2)
E_tgs_c = AES.new(K_tgs, AES.MODE_ECB)
Ticket_tgs = E_tgs.encrypt(pad(ticket_content, BLOCK_SIZE))

#Ticket for v: ticket_v
#E(K_v,[K_c_v||ID_c||AD_c||ID_v||TS4||Lifetime4])
time.sleep(1) # sleep for 1 sec to get different time stamps 
TS4 = int(time.time())
print("TS4: ", TS4)
lifetime4 = 86400
ticket_content_v = assemble2bytes(K_c_v, ID_c, AD_c, ID_v, TS4, lifetime4)
E_tgs_c = AES.new(K_v, AES.MODE_ECB)
Ticket_tgs_c = E_tgs_c.encrypt(pad(ticket_content_v, BLOCK_SIZE))

#Authenticator_c for (4) TGS -> C
#msg4 is encrypted
#msg4 = E(K_c_tgs,[ID_c||AD_c||TS3])
authenticator_content = assemble2bytes(ID_c, AD_c, TS3)
E_tgs_c = AES.new(K_c_tgs, AES.MODE_ECB)
Authenticator_c = E_tgs_c.encrypt(pad(authenticator_content, BLOCK_SIZE))
msg4 = assemble2bytes(K_c_v, ID_v, TS4, ticket_content_v)

############ My Logic Got Kinda Wonky Here ###############

#compose msg5 (6) C -> V
#decrypt msg4
msg4_dec = E_tgs_c.decrypt(msg4)
ticket_content_v = disassemble2bytes(msg4_dec)[4]

#Authenticator_c for V
#msg5 = Ticket_v||Authenticator_c
time.sleep(1) # sleep for 1 sec to get different time stamps 
TS5 = int(time.time())
authenticator_content = assemble2bytes(ID_c, AD_c, TS5)
E_c_v = AES.new(K_c_v, AES.MODE_ECB)
Authenticator_c = E_c_v.encrypt(pad(authenticator_content, BLOCK_SIZE))
msg5 = assemble2bytes(ID_v, ticket_content_v, Authenticator_c)

#compose msg6 (6) V -> C
#decrypt msg 5
msg5_dec = E_c_v.decrypt(msg5)
Ticket_tgs_content = disassemble2bytes(msg5_dec)[4]

#msg6 = E(K_c_v,[TS5 + 1])
time.sleep(1) # sleep for 1 sec to get different time stamps 
TS5 = int(time.time())
authenticator_content = assemble2bytes(ID_c, AD_c, TS5)
E_c_v = AES.new(K_c_v, AES.MODE_ECB)
Authenticator_c = E_c_v.encrypt(pad(authenticator_content, BLOCK_SIZE))
msg6 = assemble2bytes( authenticator_content ,TS5 + 1)




