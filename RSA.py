#!/usr/bin/env python3
# Robert Sturzbecher 2022-04-20
# RSA encryption tool for assessment project

from signal import raise_signal
import sys
import os.path
import rsa
# import argparse
# import hashlib
# import zlib       # optional future feature, compress the data before encrypting as zip after encrypting is useless
#from functools import partial


class colors:                                               # ANSI terminal color escape codes, excuse my american spelling here but that is how the ANSI standard spells it ;)
    RED = '\033[91m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    END = '\033[0m'


def printHelp():
    print("Usage: rsa.py [filename]\n")
    return


def generateKeys():                                         # Generate and save the keypair files.
    (publicKey, privateKey) = rsa.newkeys(1024)                 # Can be 512, 1024, 2048, 4096. 512 is easy to crack, 4096 offers better security
    with open('id_rsa.pub', 'wb') as f:                         # Open id_rsa.pub in Write and Binary mode 
        f.write(publicKey.save_pkcs1('PEM'))                    # write publice key to file
        f.close()
    with open('id_rsa', 'wb') as f:                             # Open id_rsa in Write and Binary mode
        f.write(privateKey.save_pkcs1('PEM'))                   # write private key to file
        f.close()


def loadPublicKey():                                        # here we load the public key that is used for encrypting a file
    with open('id_rsa.pub', 'rb') as f:
        publicKey = rsa.PublicKey.load_pkcs1(f.read())          # load public key from file
        print(f'PublicKey:\n{publicKey}\n')                     # Print the loaded private key, for debugging  
        f.close()
    return publicKey


def loadPrivateKey():                                       # here we load the private key that is used for decrypting a file
    with open('id_rsa', 'rb') as f:
        privateKey = rsa.PrivateKey.load_pkcs1(f.read())        # load private key from file
        print(f'PrivateKey:\n{privateKey}\n')                   # Print the loaded private key, for debugging  
        f.close()
    return privateKey


def encrypt(message, publicKey):                           # encrypt a string
    return rsa.encrypt(message.encode('ascii'), publicKey)


def decrypt(ciphertext, privateKey):                       # decrypt a string
    try:
        return rsa.decrypt(ciphertext, privateKey).decode('ascii')
    except:
        return False


def encryptFile(inputFilename, outputFilename, publicKey): # use the public key to encrypt a file
    try:
        f = open(inputFilename, mode='rb')                      # rb = Read, binary mode 
        inputfileData = f.read()
        f.close()
        f = open(outputFilename, mode='wb')                     # wb = write, binary mode 
        f.write(rsa.encrypt(inputfileData, publicKey))          # encrypt and write the data
        f.close()
        return 
    except OSError:                                             # error opening file, may not exist or can not access for some other reason
        print(f"{colors.RED}Error opening files{colors.END}")
        sys.exit()  

def decryptFile(inputFilename, outputFilename, privateKey): # use the public key to encrypt a file
    try:
        f = open(inputFilename, mode='rb')                      # rb = Read, binary mode 
        inputfileData = f.read()
        f.close()
        f = open(outputFilename, mode='wb')                     # wb = write, binary mode 
        f.write(rsa.decrypt(inputfileData, privateKey))         # decrypt and write the data
        f.close()
        return 
    except OSError:                                             # error opening file, may not exist or can not access for some other reason
        print(f"{colors.RED}Error opening files {colors.END}")
        sys.exit() 


def checkKey():
    if os.path.exists('id_rsa.pub'):                            # Check if we have a publickey saved already
        print('Public key found')
    else:                                                           
        print('Public key not found. Creating new keypair')
        generateKeys()                                          # No public key found, so call generateKeys() to create and save a keypair 
       

def main():
    print(f"{colors.GREEN}RSA Encrypter [Robert Sturzbecher]{colors.END}") 
    if len(sys.argv) != 2 :                                     # correct usage would return 2, this script full filename and the filename of the file to enc/decrypt
        print(f"{colors.RED}Error: Filename argument missing{colors.END}")
        printHelp()
    elif str(sys.argv) == "-h":                                 # Print help screen help 
        printHelp()                 
    else :
        checkKey()
        filename=sys.argv[-1]                                   # gets the last argument, if non given it will return this script filename 
        print(f"{colors.YELLOW}File: {filename}{colors.END}")
        if filename[len(filename)-4:] == '.enc':                
            print('Filename extension implies encrypted file. Attempting to decypt file')
            if os.path.exists('id_rsa'):                        # Check if we have a privatekey saved already
                decryptFile(filename, filename[0:len(filename)-4]+'.dec', loadPrivateKey())    # replace the enc file extention with dec in newly created decoded file 
            else:
                print(f'{colors.RED}Private key missing, copy the "id_rsa" file into this directory and try again{colors.END}')    
        else:
            encryptFile(filename, filename+".enc", loadPublicKey()) #we are going to encrpt and append the .enc file suffix 


if __name__ == "__main__":    
    main()