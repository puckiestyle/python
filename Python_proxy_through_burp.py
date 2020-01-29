import requests
proxy = { "http" : "http://localhost:8080" }
requests.post(targeturl, data{}, proxies=proxy)
