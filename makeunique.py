s = set()
f = open("fsocity.dic.uniq", 'r')

count =0
while True:
	count += 1
	line = f.readline()
	if not line:
		break
	else:
		s.add(line)
		print("reading lines:" + str(count))
f.close()

newfile = open("unique.txt", 'w')
newcount = 0
for i in s:
	newfile.write(i)
	newfile.write("\n")
	newcount += 1
newfile.close()
print("total: "+ str(newcount))

