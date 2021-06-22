#!/usr/bin/python3

import socket
import sys
import base64
import html

HOST="192.168.90.112"
PORT=50000

s = None
def connect():
    global s
    s = socket.socket()
    s.connect((HOST,PORT))

username = b"bob"
password = b"cookie1"

# Example:
# 1\x00admin\x00password\x00
def login():
    connect()
    buf = b""
    buf += b"1"
    buf += b"\x00"
    buf += username
    buf += b"\x00"
    buf += password
    buf += b"\x00"

    s.send(buf)
    r = s.recv(4096)
    data = r.split(b"\x00")

    s.close()
    if int(data[0]) == 1:
        return data[1].decode()
    else:
        return None

# Example:
# 2\x00commands\x00
def send_command(uuid, cmd, *args):
    connect()
    buf = b""
    buf += b"2"
    buf += b"\x00"
    buf += uuid.encode()
    buf += b"\x00"
    buf += cmd.encode()
    buf += b"\x00"
    if args != ():
        for x in args:
            buf += x.encode()
            buf += b"\x00"

    s.send(buf)
    r = s.recv(25600)
    # Sometimes we do not always receive all the data in one call. This makes sure we get it all.
    for i in range(50):
        r += s.recv(25600)
    data = r.split(b"\x00")

    s.close()
    if int(data[0]) == 1:
        return data[1].decode()
    else:
        return None

#TODO program some of the example functions that we can show to the client
uuid = login()
s = sys.argv[1]
result = send_command(uuid, "curl", f"http://127.0.0.1:8080?echostr={s}")
if result != 'ERROR':
    # Sometimes python struggles with missing padding. Add some, it will ignore the extra.
    decoded = base64.b64decode(result + '========').decode()
    # Result comes html escaped. Unescape it so it's easier to read.
    decoded = html.unescape(decoded)
    print(decoded)
