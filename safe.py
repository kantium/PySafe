#!/usr/bin/python3.4

#Stéphane Küng
#28 septembre 2015

import argparse
import getpass
import json
import os.path


from collections import OrderedDict
from base64 import b64encode, b64decode 
from Crypto.Hash import SHA256 
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


HASH_ITERATION = 100000
HASH_SALT = "0961bede606efbaeddd29"


class SafeException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

#Convert bytes to a string
def bytes_to_string(b):
    return str(hexlify(b),'UTF-8')

#Convert bytes to a base 64 string
def bytes_to_b64(b):
    return str(b64encode(b),'UTF-8')

#Convert a base 64 string to bytes
def b64_to_bytes(b64):
    return b64decode(b64)

#Decrypt a ciphertext and test digest using GCM AES Mode.
#Raise an exception if digest doesn't match
def decrypt_GCM(key, nonce, ciphertext, digest):
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(digest)
    except:
        raise SafeException("Key incorrect or message corrupted")
    return plaintext

#Encrypt a plaintext using GCM AES Mode 
#(which require a nonce and symetric key)
def encrypt_GCM(key, nonce, plaintext):
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    return cipher.encrypt(plaintext),cipher.digest()

def sha256(data):
    digest = SHA256.new() 
    digest.update(data) 
    return digest.digest()

def loadSafe(filename):

    print("loading {0}".format(filename))

    if not os.path.isfile(filename):
        raise SafeException("File doesn't exist")  

    try:
        with open(filename, 'r') as infile:
            filecontent = json.loads(infile.read())
        if len(filecontent)!=3:
            raise
    except:
        raise SafeException("File {0} is not a Safe file or is corrupted".format(filename))

    nonce,ciphertext,cipherdigest = [b64_to_bytes(x) for x in filecontent]

    key = getPassword()
    plaintext = decrypt_GCM(key, nonce, ciphertext, cipherdigest) 
    
    plainjson = json.loads(str(plaintext,'UTF-8'))
    if type(plainjson) == str:
        raise SafeException("Unable to read safe content")

    return plainjson,key

def getPassword(message="Password: "):
    password = sha256(getpass.getpass(message) + HASH_SALT)
    for i in range(HASH_ITERATION):
        password = sha256(password)
    return password

def getVerifiedPassword(message1="New Password: ",message2="Verify Password: "):    
    while True:
        p1 = getPassword(message1)
        p2 = getPassword(message2)

        if (p1==p2):
            return p1
        else:
            print("Password don't match. Try again")

def printAbout():
    print("\
 ______     ______     ______   ______    \n\
/\  ___\   /\  __ \   /\  ___\ /\  ___\       \n\
\ \___  \  \ \  __ \  \ \  __\ \ \  __\       \n\
 \/\_____\  \ \_\ \_\  \ \_\    \ \_____\     \n\
  \/_____/   \/_/\/_/   \/_/     \/_____/  by Stéphane Küng in 2015\n")

def saveSafe(filename, plainjson, key):

    plaintext = json.dumps(plainjson)
    nonce = get_random_bytes(32)

    ciphertext,cipherdigest = encrypt_GCM(key, nonce, plaintext)
    cipher_contener = [bytes_to_b64(x) for x in (nonce, ciphertext, cipherdigest)]
    
    try:
        with open(filename, 'w') as outfile:
            json.dump(cipher_contener, outfile)
    except:
        raise SafeException("Unable to save file {0}".format(filename))

    print("{0} saved".format(filename))

def SafeManager(filename, action):

    if action in ("edit","add","show","remove","list","passwd"):
        plainjson,key = loadSafe(filename)

    if (action=="add"):
        print("Add new title/value")

        new_title = input("Title: ")
        if new_title in plainjson:
            raise SafeException("Title already exist")
        else:
            new_value = input("Value: ")
            plainjson[new_title] = new_value
 
    if (action=="show"):
        print("Show a value for a given title")
        title = input("Title: ")

        if title in plainjson:
            print("Value: {0}".format(plainjson[title]))
        else:
            print("Title not found")

    if (action=="remove"):
        print("Remove a value for a given title")

        title = input("Title: ")

        if title in plainjson:
            del(plainjson[title])
        else:
            print("Title not found")

    if (action=="edit"):
        print("Edit a value for a given title")   

        title = input("Title: ")

        if title in plainjson:
            new_value = input("New value: ")
            plainjson[title] = new_value
        else:
            print("Title not found")

    if (action=="list"):
        if len(plainjson)==0:
            print("This safe is empty !")
        else:
            print("List all title/value")

        for item in OrderedDict(sorted(plainjson.items())):
            hidden = len(plainjson[item])*"*"
            print("Title: {0:13} Value: {1:13}".format(item,hidden))

    if (action=="newfile"):
        print("Create a new Safe File")
        key = getVerifiedPassword()
        plainjson = {}
        
    if (action=="passwd"):
        key = getVerifiedPassword()
        print("Password changed")

    if action in ("edit","add","remove","newfile","passwd"):
        saveSafe(filename, plainjson, key)

    if action in ("about"):
        printAbout()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Safebox')
    parser.add_argument('--action', '-a', required=True, choices=['add', 'show', 'remove', 'edit', 'list', 'newfile', 'passwd', 'about'])
    parser.add_argument('--filename','-f',default='./local.txt')
    
    args = parser.parse_args()
    try:
        SafeManager(args.filename,args.action)
    except SafeException as e:
        print("Error: " + e.value) 

