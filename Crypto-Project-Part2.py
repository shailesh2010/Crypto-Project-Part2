import socket,time, os, sys, getpass, hashlib
#import threading

import base64
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP   

## Constants
tempKey = b'ed19z2t4G68hjrKjGt2VYhar8W5U0w5o'
IV = 'bfJOwqj7QX7Taqn9'
BLOCK_SIZE=32

PRIV_KEY_LOC = "keys.der"
PUB_KEY_LOC = "pubkeys.der"


#### Encryption algorithm
def RSA_encrypt(aes_key):
    pubkey = open(PUB_KEY_LOC, "r").read()           # open the SSH public key of the destination server
    rsakey = RSA.importKey(pubkey)                      # import the public key
    rsakey = PKCS1_OAEP.new(rsakey)                     # create the cipher using OAEP with RSA
    encKey = rsakey.encrypt(aes_key)
    return encKey


def RSA_decrypt(encAESKey):
    privkey = open(PRIV_KEY_LOC, "r").read()         # open the SSH private key used for decryption
    rsakey = RSA.importKey(privkey)
    rsakey = PKCS1_OAEP.new(rsakey)                     # use OAEP to create cipher for decryption
    aes_key = rsakey.decrypt(encAESKey)     
    return aes_key

def encrypt(message,key):
    #IV = Random.new().read(16) 
    c = AES.new(key, AES.MODE_CFB, IV) 
    #data = message.encode('utf-8') #  1
    data = c.encrypt(message) #  2
    return data

def decrypt(ciphertext,key):
   c = AES.new(key, AES.MODE_CFB, IV) 
   data = c.decrypt(ciphertext) # 1
  # data = data.decode('utf-8') # 2
   return data
#### Encryption algorithm


def readData(socket, Flag, clientKey, serverKey, Token):
    encData = socket.recv(86)
    decData1 = decrypt(encData[0:int(len(encData)/2)],clientKey)
    decData2 = decrypt(encData[int(len(encData)/2):],serverKey)
    command = decData1 + decData2
    
    #print(">> Inside read", command)
    command = command.decode('ascii')
    newToken = command[0:32]
    oldToken = command[32:64]
    if not TokenCheck(Token, oldToken):
        return (None,None)
    command = command[64:]
    request = None
    data = None
    if command[0:2] == 'NC':
        requestSize = int(command[2:18])
        request = command[18:22]
        socket.send(b'11'*10)
        if Flag:
            data = socket.recv(requestSize).decode('ascii')
        else:
            data = socket.recv(requestSize)
        socket.send(b'11'*10)
    return(request, data, newToken)
    
def writeData(command, data, socket, Flag, clientKey, serverKey, Token):
    requestSize = '%016d' % int(len(data))    
    newToken = getToken(False)
    request = newToken + Token + "NC" + requestSize + command
    #print("\n>> Inside send", request)
    encData1 = encrypt(request[0:int(len(request)/2)],clientKey)
    encData2 = encrypt(request[int(len(request)/2):],serverKey)
    encData = encData1 + encData2    
    socket.send(encData)
    signal = socket.recv(2*10)
    if signal == b'11'*10:
        if Flag:
            socket.send(data.encode('ascii'))
        else:
            socket.send(data)            
    signal = socket.recv(2*10)
    return newToken

def getToken(Flag):
    currentTime = time.time()
    m = hashlib.md5()
    m.update(str(currentTime).encode('ascii'))
    if Flag:
        return m.hexdigest().encode('ascii')
    else:
        return m.hexdigest()

def TokenCheck(OldToken, NewToken):
    if OldToken != NewToken:
        print("Replay attack detected shutting down")
        return False
    return True

def startClient():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hostname = sys.argv[2]                           
    port = 8080
    clientKey = os.urandom(32)
    serverKey = None
    ClientToken = None
    ServerToken = None
    s.connect((hostname, port))
    print(">>> Starting client....")
    print("Enter credentials for login")
    username = input("Enter User Name: ")
    password = getpass.getpass("Enter Password: ")
    print(">>> Connecting to server...")
    s.send(b'SYNC')
    signal = s.recv(2*10)
    if signal != b'11'*10:
        print('Sync Failure shutting down')
        s.close()
        return    
    ClientToken = getToken(False)    
    ClientKeyCipher = RSA_encrypt(clientKey)
    s.send(ClientToken.encode('ascii'))
    s.send(ClientKeyCipher)
    ServerToken = s.recv(32).decode()
    if not TokenCheck(ClientToken,ServerToken):
        s.close()
        return
    ServerToken = s.recv(32).decode()
    serverKey = decrypt(s.recv(256), clientKey)
    print(">>> Session Connected...")
    print(">>> Attempting Login...")
    credentials = username + ',' + password 
    credentials = credentials
    ClientToken = writeData('AUTH', credentials , s, True, clientKey, serverKey, ServerToken)
    request, data , ServerToken = readData(s, True, clientKey, serverKey, ClientToken)
    if(data != None and data != "Success"):
        print('Login Failure shutting down')
        s.close()
        return    
    print(">>> Login Success...")
    input(">>> Begin File transfer (Y): ")
    file = open(sys.argv[3] , 'rb')
    filesize = file.seek(0, os.SEEK_END)
    file.seek(0)
    filename = sys.argv[3].split("\\")
    filename = filename[len(filename)-1]
    ClientToken = writeData('FILE', str(filesize) , s, True, clientKey, serverKey, ServerToken)
    ClientToken = writeData('FNAM', filename , s, True, clientKey, serverKey, ServerToken)
    ServerToken, ClientToken = writeFile(file, filesize, s, clientKey, serverKey, ServerToken, ClientToken)
    file.close()
    input("Press any key to terminate client")
    ClientToken = writeData('CLOS', 'CLOSE' , s, True, clientKey, serverKey, ServerToken)
    s.close()
    
def startServer():
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = "127.0.0.1"
    port = 8080                                           
    print(">>>> starting server...")
    serversocket.bind((host, port))                                  
    serversocket.listen(15)                                           
    while True:
        clientsocket,addr = serversocket.accept()
        print("Got a connection from %s" % str(addr))
        serverRequestHandler(clientsocket)
        #threading.start_new_thread(serverRequestHandler,(clientsocket))

def serverRequestHandler(clientsocket):
    serverKey = os.urandom(32)
    clientKey = None
    username = None
    ServerToken = None
    ClientToken = None
    print(">>> Waiting for client keys...")
    signal = clientsocket.recv(4)
    if signal != b'SYNC':
        print('Sync Failure shutting down')
        clientsocket.close()
        return
    clientsocket.send(b'11'*10)
    ClientToken = clientsocket.recv(32)    
    ClientKeyCipher = clientsocket.recv(256)    
    clientKey = RSA_decrypt(ClientKeyCipher)
    ServerToken = getToken(True)
    clientsocket.send(ClientToken)
    clientsocket.send(ServerToken)
    clientsocket.send(encrypt(serverKey,clientKey))
    print(">>> Session connected...")
    ServerToken = ServerToken.decode()
    while True:
        #print("> Waiting for request")
        request, data , ClientToken = readData(clientsocket, True, clientKey, serverKey, ServerToken)
        #print("> Got", request, ' and ', data)
        if (request != None):
            print("> Got client request")
            if (request == 'AUTH'):
                credentials = data.split(',')
                print('Got credentials from client')
                print('Username:', credentials[0], ' Password', credentials[1])
                print('>>> Sending available files list')
                ServerToken = writeData('AUTH', "Success" , clientsocket, True, clientKey, serverKey, ClientToken)
                # send file list
            if(request == 'FILE'):                
                request, data , ClientToken = readData(clientsocket, True, clientKey, serverKey, ServerToken)
                if (request!= None and request == 'FNAM'):
                    FileName = data
                    ClientToken, ServerToken = readFile(clientsocket, FileName, clientKey, serverKey, ClientToken, ServerToken)
            if(request == 'CLOS'):
                print(">>> Closing Client...")
                clientsocket.close()
                return
        else:
            print(">>> Data interuppted...")
            print(">>> Closing Client...")
            clientsocket.close()
            

def writeFile(file, filesize, s, clientKey, serverKey, ServerToken, ClientToken):
    while file.tell() < filesize:
        FileContent = file.read(30720)
        if(len(FileContent) < 30720):
            ClientToken = writeData('FEND', FileContent, s, False, clientKey, serverKey, ServerToken)
            print(">> File transmission Completed")
            return (ServerToken, ClientToken)
        else:
            ClientToken = writeData('FDAT', FileContent, s, False, clientKey, serverKey, ServerToken)    
    return (ServerToken, ClientToken)    

def readFile(clientsocket, FileName, clientKey, serverKey, ClientToken, ServerToken):
    file = open("C:\\a\\Server_" + FileName,'wb')
    while True:
        request, data , ClientToken = readData(clientsocket, False, clientKey, serverKey, ServerToken)
        if(request!= None and request == 'FDAT'):
            file.write(data)
        elif(request!= None and request == 'FEND'):
            file.write(data)
            file.close()
            print('> File transmission Completed')
            return (ClientToken, ServerToken)
    return (ClientToken, ServerToken)

        
def main():
    method = sys.argv[1]	# read the first command line argument to this python script
    if(method == "server"):
            startServer()	# if the argument is equal to "server" start FTP server
    elif(method == "client"):
            startClient()	# if the argument is "client" continue as a client
    else:
            print ("Unknown method! Exiting..")	# if the argument is unknown, exit program
            exit()

if __name__=="__main__":
	main()			# run the main function
    

