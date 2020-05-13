#asymmetric encryption
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

#declaring required variables for ciphertext,message,cipher IV, cipher key, public and private key.
mt=ct=msg=m=y=civ=ck=private_key=public_key=None               

backend = default_backend()
key = os.urandom(32)
iv = os.urandom(16)

class asyenc:

    def __init__(self, name):
        self.name=name
    
    global private_key, public_key

    #to produce instance's private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=backend) 

    #to produce instance's public key            
    public_key = private_key.public_key()                                                           


    #class method that returns serialized private key
    def privkey(self):                                                                              
        
        self.prk = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())

        return self.prk


    
    #class method that returns serialized public key
    def pubkey(self):                                                                               

        self.puk = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
     
        return self.puk


    
    #class method that returns digital signature wrt to message entered
    def signn(self,message):                                                                        

        self.signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256())
        return self.signature

    
    #class method that verifies the authenticity of the digital signature
    def veri(self,signature,message):                                                               

        public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256() )
        print("\nDIGITAL SIGNATURE VERIFICATION SUCCESSFUL. ENCRYPTED KEY RECEIVED IS AUTHENTIC.")

    
    #class method returns encrypted message
    def encr(self,message):                                                                         
        self.ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
             algorithm=hashes.SHA256(),
            label=None
        )
        )
        return self.ciphertext

    
    #class method that returns decrypted message
    def decr(self,ciphertext):                                                                      


        self.plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
        return self.plaintext
        



#declares required instances of class
alice= asyenc("Alice")                                                                              
bob= asyenc("Bob")


#method to print public and private key of instance
def one(d):                                                                                         
    x=d.privkey()
    y=d.pubkey()
    print("\nPrivate Key of ",d.name," is ",x)
    print("\n Public Key of ",d.name," is ",y)



#method to send symmetric key between instances by encrypting
def sen(a, b):                                                                                      
    global ck,civ,y,m,key,iv
    print("\nSessional Key generated is : \n",key)
    print("\nSessional IV generated is : \n",iv)
    ck = b.encr(key)
    civ = b.encr(iv)
    print("\nCrypted Sessional Key is : \n",ck)
    print("\nCrypted Sessional IV  is : \n",civ)
    m=(input("\n\nEnter Signature of Sender: "))
    m=m.encode()
    y= a.signn(m)
    print("\nDigital Signature of sender generated as:\n",y)
    print("\nEnrypted Key along with Digital Signature sent.")


#method to verify the encrypted symmetric key received
def rec(a, b):                                                                                       
    global k,i,y,m
    k = b.decr(ck)
    i = b.decr(civ)
    print("\nDecrypted Sessional Key received is : \n",k)
    print("\nDecrypted Sessional Key received is : \n",i)

    a.veri(y,m)


#method to send message with digital signature between instances
def sm(a,b):
    global msg,m,ct,y
    msg=(input("\nEnter message sender wants to send is: "))
    msg=msg.encode()
    ct=b.encr(msg)
    m=(input("\n\nEnter Signature of Sender: "))
    m=m.encode()
    y= a.signn(m)
    print("\nDigital Signature of sender generated as:\n",y)
    print("Encrypted message is: ",ct)


#method to decrypt received ciphertext and verify digital signature received
def rm(a,b):
    global m,y,mt
    mt=b.decr(ct)
    mt=mt.decode()
    a.veri(y,m)
    print("\nThe decrypted message from ",a.name," to ",b.name," is:\n",mt)



#main method
def main(): 
    
    x="y"

    while x is "y" or x is "Y":
        print("\nMAIN MENU:\n")
        print("1.Generate Alice's pair of public and private keys")
        print("2.Generate Bob's pair of public and private keys")
        print("3.Send a symmetric key from Alice to Bob")
        print("4.Recieve the key")
        print("5.Send a message from alice")
        print("6.Send a message from bob")
        print("7.Exit") 
        n=int(input("\nEnter your choice: "))
        
        if n is 1:
            print("hi")
            one(alice)
        elif n is 2:
            one(bob)
        elif n is 3:
            sen(alice,bob)
        elif n is 4:
            rec(alice,bob)
        elif n is 5:
            sm(alice,bob)
            rm(alice,bob)
        elif n is 6:
            sm(bob,alice)
            rm(bob,alice)
        elif n is 7:
            exit
        

        #to loop main
        x=input("\nBack to menu?(y/Y) ")




if __name__ == "__main__":
     main() 

    

    

    






