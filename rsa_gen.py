
import rsa
(publicKey,privateKey) =  rsa.newkeys(2048,accurate=True)

with open("C:/Users/tej/Desktop/publicKey.txt", "wb") as binary_file:
    binary_file.write(publicKey.save_pkcs1())

with open("C:/Users/tej/Desktop/privateKey.txt", "wb") as binary_file:
    binary_file.write(privateKey.save_pkcs1())