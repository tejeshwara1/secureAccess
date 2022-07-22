from inspect import signature
import socket
import rsa,time

# from client import packetMaker

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

def to_sign(challenge):

    # Simulating Fetching of Previously Generated Private Key 
    with open("C:/Users/tej/Desktop/privateKey.txt", "rb") as file:
        privateKey = rsa.PrivateKey.load_pkcs1(file.read())

    sign = rsa.sign(challenge, privateKey, hash_method='SHA-256')
    return sign

def datasplit(data):
    if data[:8]=='01220301':
        cLen = int(data[8:12],16)
        challenge = bytes.fromhex(data[12 : 12+cLen*2])
        signature=to_sign(challenge)
        print(signature)
        response=packetMaker('03','62','0301',signature)
    else:
        response=packetMaker('03','7F','22',b'')
    return response

def connect_client():
    s = socket.socket()		# next create a socket object
    print ("Socket successfully created")
    port=6500             #connect to port it is 1707		
    s.bind(('',port))	    #bind to port 		
    print ("socket binded to %s" %(port))
    s.listen(3)	            #put the socket into listening mode
    print ("socket is listening")		
                            # a forever loop until we interrupt it or an error occurs
    while True:
        c,addr = s.accept()	# Establish connection with client.
        print ('Got connection from', addr )
                             #request-response code do here

        
        # Close the connection with the client
        request_packet=c.recv(1024).hex()
        # print(request_packet)
        # request_packet=str(request_packet)
        res=datasplit(request_packet)
        c.send(res)
        c.close()
        # Breaking once connection closed

connect_client()