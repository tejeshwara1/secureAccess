
import socket
import random
import rsa
import time
import os
import sys
import subprocess,string


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






def reset():
    conn.send(packetMaker('02', '7f', '030127', b''))
    print("Resetting Connection...")
    conn.close()
    ecu_socket.close()
    subprocess.call([sys.executable, os.path.realpath(__file__)] +sys.argv[1:])



def wait_for_request():
    while True:
        data = conn.recv(1024).hex()
        if data[:8] == '01220401':
            print("2.Tester asking for challenge")
            return
        else:
            reset()



def recieve_sign():
    while True:
        # Recieve Signature to verify from Tester
        data = conn.recv(1024).hex()

        if data[:8] == '01270301':
            signLen = int(data[8:12],16)
            signature = bytes.fromhex(data[12 : 12+signLen*2])
            print("5.Signature Recieved")
            print(signature)
            return signature
        
        else:
            reset()




if __name__ == '__main__':
    
    host = socket.gethostname()
    port = 5000 
    ecu_socket = socket.socket()  
    ecu_socket.bind((host, port)) 
    ecu_socket.listen(1)
    print("ECU is ready")
    conn, address = ecu_socket.accept() 

    while True:
            # wait for challenge request
            wait_for_request()


            # Simulating getting Random String from HW Crypto Driver
            # and sending challenge to tester     
            challenge = random.randbytes(16)
            print(challenge.hex())
            print("Challenge Generated: "+str(challenge))
            conn.send(packetMaker('02', '62', '0401', challenge))


            # Waiting for Signed Challenge
            signature = recieve_sign()

            

            # Simulating getting public key from HSM 
            with open('C:/Users/tej/Desktop/publicKey.txt',"rb") as file:
                publicKey = rsa.PublicKey.load_pkcs1(file.read())

        

            # Verify Signature
            try:
                rsa.verify(challenge, signature, publicKey)
                print("6.Access Granted")
                conn.send(packetMaker('02', '67', '0301', b''))

            except:
                print("6.Access Denied")
                conn.send(packetMaker('02', '7f', '030127', b''))


