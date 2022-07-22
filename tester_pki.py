import socket
import time
import rsa
import sys
import random



def packetMaker(s_id, cmd, sub_cmd,data):
        s_id = bytes.fromhex(s_id)
        cmd = bytes.fromhex(cmd)
        sub_cmd = bytes.fromhex(sub_cmd)
        dLen = bytes.fromhex('{0:04X}'.format(len(data)))
        packet = bytearray(s_id)+\
                 bytearray(cmd)+\
                 bytearray(sub_cmd)+\
                 bytearray(dLen)+\
                 bytearray(data)
        return packet



def wait_for_signature():
    print("waiting for signature")
    while True:
        data = pki_socket.recv(1024).hex()
        if data[:8]=='03620301':
            # print(data[12:])
            signature_pki=bytes.fromhex(data[12:])
        return signature_pki


host = socket.gethostname() 
port = 6500 
pki_socket = socket.socket() 
pki_socket.connect(('127.0.0.1', port))  

while True:
    ch = bytes.fromhex(sys.argv[1])
    pki_socket.send(packetMaker('01', '22', '0301',ch) )

    signature = wait_for_signature()
    with open("C:/Users/tej/Desktop/ipcsign.txt","wb") as f:
        f.write(signature)

    pki_socket.close()  # close the connection
    break


