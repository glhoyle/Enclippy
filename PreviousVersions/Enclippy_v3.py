import argparse
import base64
import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.fernet import Fernet

parser = argparse.ArgumentParser(
	description='Use a password to encrypt and decrypt files.')
parser.add_argument('-o', '--overwrite', dest='overwrite', action='store_const',
                    const=True, default=False,
                    help='overwrite the input file with the enclipted/declipted version')
parser.add_argument('filePath', type=str,
				    help='path to input file')
parser.add_argument('password', type=str,
				    help='password to use when enclipting or declipting')
parser.add_argument('mode', type=str, default="enclip",
				    help='"enclip" or "declip" the given file')

args = parser.parse_args()

providedPass = args.password
encodedPass = providedPass.encode()

filename = args.filePath

mode = args.mode


# encrypting the file
def enclip(filename):
    salt = b'd8fben47chfbdng6' # currently using a fixed salt
    kdf = PBKDF2HMAC (
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend() # other backends are depreciated
    )
    key = base64.urlsafe_b64encode(kdf.derive(encodedPass))

    # output key to file - need to clear key file before every new file :(
    # do an error catch and loop through all keys until either one works or none work
    keyFile = open("keys.txt", 'a')
    keyFile.write(key.decode())
    keyFile.write('\n')
    keyFile.close()

    enclipFile = open(filename, 'rb')
    fileContents = enclipFile.read()
    enclipFile.close()

    f = Fernet(key)
    encrypted = f.encrypt(fileContents)
    # print(encrypted)

    # writing to file

    enclipFileName = filename + ".enclip"
    f = open(enclipFileName, 'wb')
    f.write(encrypted)
    f.close()
    print(key)
    print("File enclipted: " + enclipFileName)

def declip(filename):
    declipFile = open(filename, 'rb')
    fileContents = declipFile.read()
    declipFile.close()

    # start copy
    salt = b'd8fben47chfbdng6' # currently using a fixed salt
    kdf = PBKDF2HMAC (
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend() # other backends are depreciated
    )
    key = base64.urlsafe_b64encode(kdf.derive(encodedPass))
    # end copy
    print(key)

    keyExists = False

    keyFile = open("keys.txt", 'r')
    for x in keyFile:
        if x.strip() == key:
            keyExists = True

    if (not(keyExists)):
        keyFile.close()
        sys.exit("This password is wrong. Fuck you! :)")

    keyFile.close()

    f = Fernet(key)
    decrypted = f.decrypt(fileContents)
    #print(decrypted)



    # writing to file
    filename = "declip_" + filename
    declipFileName = filename.replace(".enclip", "", 1)
    f = open(declipFileName, 'wb')
    newContents = decrypted
    f.write(newContents)
    f.close()
    # implement remove .enclip file
    print("File declipted: " + declipFileName)


if (mode == "enclip"):
    enclip(filename)
elif (mode == "declip"):
    declip(filename)
else:
    print("You must provide the option 'enclip' or 'declip'.")