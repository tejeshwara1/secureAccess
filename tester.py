
import socket
import time
import rsa



def modify_sig(signature):
    hex_string = signature.hex()
    modified = 'f'+ hex_string[1:]
    return bytes.fromhex(modified)



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



def to_pki(challenge):

    # Simulating Fetching of Previously Generated Private Key 
    with open("C:/Users/tej/Desktop/privateKey.txt", "rb") as file:
        privateKey = rsa.PrivateKey.load_pkcs1(file.read())

    sign = rsa.sign(challenge, privateKey, hash_method='SHA-256')
    print("from pki fun"+str(sign))

    return sign



def wait_for_challenge():
    print("waiting for challenge")
    while True:
        data = ecu_socket.recv(1024).hex()
        if data:
            cLen = int(data[8:12],16)
            challenge = bytes.fromhex(data[12 : 12+cLen*2])
            print("Challenge Recieved: "+str(challenge))
            return challenge




def wait_for_grant():
    while True:
        msg = ecu_socket.recv(1024).hex()
        print(msg)
        if msg[:8]=='02670301':
            print("Access Granted")
            return
        
        if msg[:10]=='027f030127':
            print("Access Denied")
            return

        else:
            print("Sequence Error")








    
host = socket.gethostname() 
port = 5000 
ecu_socket = socket.socket() 
ecu_socket.connect((host, port))  

while True:
    print("Enter 1 to Request Secure Access")
    if input()== '1':

        print("1.Tester sent request")
        ecu_socket.send(packetMaker('01', '22', '0401',b'')) 

        
        challenge = wait_for_challenge()
        import subprocess
        proc = subprocess.Popen(['python', 'C:/Users/tej/Desktop/tester_pki.py',challenge.hex()])
        time.sleep(5)

        with open("C:/Users/tej/Desktop/ipcsign.txt","rb") as f:
            signature = f.read()
        # signature = modify_sig(signature)
        # print(signature)



       # send signature to ECU
        data = packetMaker('01', '27', '0301', signature)
        ecu_socket.send(data)
        
        # wait for signature verification
        wait_for_grant()
        
    else:
        continue




ecu_socket.close()  # close the connection


