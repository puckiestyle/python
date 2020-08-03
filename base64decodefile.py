from base64 import *

with open('encodedflag.txt','r') as f:

  line = f.read()

for _ in range(5):

  line = b16decode(line)


for _ in range(5):

  line = b32decode(line)


for _ in range(5):

  line = b64decode(line)

print(line)

