#!/usr/bin/env python
# -*- coding: utf-8 -*-


import requests
import json
import readline


url = 'http://10.10.10.108/zabbix/api_jsonrpc.php'

login = 'zapper'
password = 'zapper'

# auth to API
payload = {
    "jsonrpc" : "2.0",
    "method" : "user.login",
    "params": {
    	'user': ""+login+"",
    	'password': ""+password+"",
    },
   	"auth" : None,
    "id" : 0,
}
headers = {
    'content-type': 'application/json',
}

auth  = requests.post(url, data=json.dumps(payload), headers=(headers))
auth = auth.json()

# find the host id

host_get = {
    "jsonrpc": "2.0",
    "method": "host.get",
    "params": {
        "output": [
            "hostid",
            "host"
        ],
        "selectInterfaces": [
            "interfaceid",
            "ip"
        ]
    },
    "id": 2,
    "auth": auth['result'],
}

host_id = requests.post(url, data=json.dumps(host_get), headers=(headers))
host_id = host_id.json()


while True:
    cmd = raw_input('\033[41m[zabbix_cmd]>>: \033[0m ')
    if cmd == "" : print "Result of last command:"
    if cmd == "quit" : break
 
# update
    payload = {
        "jsonrpc": "2.0",
        "method": "script.update",
        "params": {
            "scriptid": "1",
            "command": ""+cmd+""
        },
        "auth" : auth['result'],
        "id" : 0,
    }
 
    cmd_upd = requests.post(url, data=json.dumps(payload), headers=(headers))
 
# execute
    payload = {
        "jsonrpc": "2.0",
        "method": "script.execute",
        "params": {
            "scriptid": "1",
            "hostid": host_id['result'][0]['hostid'],
        },
        "auth" : auth['result'],
        "id" : 0,
    }
 
    cmd_exe = requests.post(url, data=json.dumps(payload), headers=(headers))
    cmd_exe = cmd_exe.json()
    print cmd_exe["result"]["value"]
