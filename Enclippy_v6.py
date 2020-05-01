# Enclippy -- Simple password-protected encryption and decryption of files.
#
# Written by: Ren Hardzog, Gracen Hoyle, and Grant Peterson
# Last modified: 4/24/2020
#
# Python version: 3.7
import argparse
import base64
from os import urandom
import os
import sys
while True:
    try:
        from cryptography.exceptions import InvalidKey
        from cryptography.fernet import Fernet
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        break
    except ImportError:
        sys.exit("The required Cryptography package was not found.\r\nPlease install it from the command line using \"pip install cryptography\".")

parser = argparse.ArgumentParser(description='Use a password to encrypt and decrypt files.')
parser.add_argument('-t', '--testing', dest='test', action='store_const',
                    const=True, default=False,
                    help='does not overwrite the input file with the enclipted/declipted version')
parser.add_argument('filePath', type=str,
				    help='path to input file')
parser.add_argument('password', type=str,
				    help='password to use when enclipting or declipting')
parser.add_argument('mode', type=str, default="enclip",
				    help='"enclip" or "declip" the given file')

args = parser.parse_args()

filename = args.filePath
if (filename == __file__):
    sys.exit("Please do not try to enclip/declip this program!")
encodedPass = args.password.encode()
mode = args.mode
test = args.test

keyFileName = ".enclip-keys"
iterationCount = 100000

# encrypt the file ============================================================
def enclip(filename):
    fileContents = ""
    
    salt = base64.urlsafe_b64encode(urandom(16))
    kdf = PBKDF2HMAC(algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = iterationCount,
        backend = default_backend() # other backends are depreciated
    )
    key = base64.urlsafe_b64encode(kdf.derive(encodedPass))
    # keyfile line format: 'filename:iterations:salt:key'
    newKeyLine = (filename + ":" + str(iterationCount) + ":" + base64.urlsafe_b64encode(salt).decode() + ":" + key.decode() + '\n')

    # Check keyfile for existing records.  If a record exists for the given
    # file, overwrite the record with the new info, otherwise append the new
    # record.  If the keyfile does not exist, create one and add the new
    # record.
    while True:
        try:
            with (open(keyFileName, "r+")) as f:
                keyFound = False
                keyFile = f.read()
                f.seek(0)
                for line in keyFile.strip().split('\n'):
                    parts = line.strip().split(":")
                    if (parts[0] == filename):
                        keyFound = True
                        f.write(newKeyLine)
                    else:
                        f.write(line + '\n')
                if (not(keyFound)):
                    f.write(newKeyLine)
                f.truncate()
            break
        except FileNotFoundError:
            with open(keyFileName, 'a+') as f:
                f.write(newKeyLine)
            break

    # read and encrypt the given file based on the generated key
    fernet = Fernet(key)
    with open(filename, 'rb') as f:
        fileContents = f.read()
    enclipted = fernet.encrypt(fileContents)

    # writing to file
    enclipFileName = filename + ".enclip"
    with open(enclipFileName, 'wb') as f:
        f.write(enclipted)
    if(not(test)):
        os.remove(filename)
    print("File enclipted: " + enclipFileName)

# decrypt the file ============================================================
def declip(filename):
    parts = []
    keyExists = False
    keyFile = open(keyFileName, 'r')
    for line in keyFile:
        parts = line.strip().split(':') # [filename, iterations, salt, key]
        if (parts[0] + ".enclip") == filename:
            keyExists = True
            break
    keyFile.close()

    if not(keyExists):
        print("Sorry, this file cannot be declipted!")
        sys.exit("error: no record in keyfile")
        
    # check given password against stored key
    kdf = PBKDF2HMAC(algorithm = hashes.SHA256(),
        length = 32,
        salt = base64.urlsafe_b64decode(parts[2]),
        iterations = int(parts[1]),
        backend = default_backend() # other backends are depreciated
    )
    while True:
        try:
           kdf.verify(encodedPass, base64.urlsafe_b64decode(parts[3]))
           break
        except InvalidKey:
           sys.exit("Sorry, your password does not match!")

    # read and decrypt the given file based on the key
    fernet = Fernet(parts[3])
    with open(filename, 'rb') as f:
        fileContents = f.read()
    declipted = fernet.decrypt(fileContents)

    # writing to file
    if(not(test)):
        os.remove(filename)
    else:
        filename = "declip_" + filename
    declipFileName = filename.replace(".enclip", "", 1)
    with open(declipFileName, 'wb') as f:
        f.write(declipted)
    print("File declipted: " + declipFileName)

# main section ================================================================
if (args.test):
    print("Testing flag is set")

if (mode == "enclip"):
    enclip(filename)
elif (mode == "declip"):
    declip(filename)
else:
    print("You must provide the option 'enclip' or 'declip'.")
