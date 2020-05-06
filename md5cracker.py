import crypt, hashlib
f = open('/usr/share/wordlists/rockyou.txt','r')
lines = f.readlines()
for line in lines:
        line = line.strip()
        m = crypt.crypt(line,'fa')
        md5 = hashlib.md5()
        md5.update(m)
        if md5.hexdigest() == 'e626d51f8fbfd1124fdea88396c35d05' :
                print 'found it ' + line
                break
