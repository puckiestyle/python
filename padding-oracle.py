#!/usr/bin/python3

import sys, urllib.parse, requests

def get_hex_byte(byte):
    hex_byte = str(hex(byte)).replace('0x', '')
    if len(hex_byte) == 1:
        hex_byte = '0' + hex_byte
    return hex_byte

def send_request(ip, port, param):
    r = requests.get(url = 'http://' + ip + ':' + port + '/?c=' + param)
    resp = str(r.content)
    idx = resp.index('MyLabel') + 9
    resp = resp[idx : idx + 1]
    return int(resp)

def main(argv):
    if len(argv) < 2:
        print('[-] Usage: python3 ' + sys.argv[0] + ' <IP> <Port>')
        return 1
    ip = argv[0]
    port = argv[1]
    # iv_orig = '4358b2f77165b5130e323f067ab6c8a9'
    iv_orig = [67, 88, 178, 247, 113, 101, 181, 19, 14, 50, 63, 6, 122, 182, 200, 169]
    # ciphertext_block = '2312420765204ce350b1fbb826c59488'
    ciphertext_block_bytes = [35, 18, 66, 7, 101, 32, 76, 227, 80, 177, 251, 184, 38, 197, 148, 136]
    ciphertext_block_hex = ''
    message_length = 0
    default_padding_byte = 0
    for j in ciphertext_block_bytes:
        ciphertext_block_hex += get_hex_byte(j)
    print('[+] Computing message length...')
    for i in range(0, 16, 1):
        server_string = ''
        for j in range(0, len(iv_orig), 1):
            if j <= i:
                server_string += '00'
            else:
                server_string += get_hex_byte(iv_orig[j])
        server_string += ciphertext_block_hex
        if send_request(ip, port, server_string) == 0:
            message_length = i
            default_padding_byte = 16 - i
            print('[+] Found message length of ' + str(i) + ' bytes')
            break
    message_bytes = []
    for i in range(0, default_padding_byte, 1):
        message_bytes.insert(0, default_padding_byte)
    print('[+] Brute-forcing message content...')
    for i in range(message_length - 1, -1, -1):
        print('[+] Brute-forcing position ' + str(i + 1) + '...')
        iv_prefix = ''
        iv_suffix = ''
        iv_target = iv_orig[i]
        for j in range(0, i, 1):
            iv_prefix += get_hex_byte(iv_orig[j])
        for j in range(i + 1, len(iv_orig), 1):
            iv_suffix += get_hex_byte(iv_orig[j] ^ message_bytes[j - i - 1] ^ (16 - i))
        for j in range(0, 256, 1):
            str_byte = get_hex_byte(j)
            request = iv_prefix + str_byte + iv_suffix + ciphertext_block_hex
            if send_request(ip, port, request) == 1:
                byte = j ^ (16 - i) ^ iv_target
                message_bytes.insert(0, byte)
                print('[+] Found byte: 0x' + str_byte)
                print('[+] Found char: ' + chr(byte))
                break
    plaintext = ''
    for byte in message_bytes:
        plaintext += chr(byte)
    print('[+] Plaintext message compromised:\n' + plaintext)

if __name__ == '__main__':
    main(sys.argv[1:])
    sys.exit(0)