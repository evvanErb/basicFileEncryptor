#!/usr/bin/python2

from Crypto.Cipher import AES
import hashlib

#setting up encryptor and decryptor
def setupEncryption():
    key = raw_input("\nWhat is your password?\n>>> ")
    key2 = raw_input("\nPlease confirm your password:\n>>> ")
    while key != key2:
        print("\n[!] Cofirmation did not match first password please re-enter")
        key = raw_input("\nWhat is your password?\n>>> ")
        key2 = raw_input("\nPlease confirm your password:\n>>> ")
    key = hashlib.sha256(key).digest()
    mode = AES.MODE_CBC
    IV = "\x00"*16
    encryptor = AES.new(key, mode, IV=IV)
    decryptor = AES.new(key, mode, IV=IV)
    return([encryptor,decryptor])

#decrpyting file
def decryptFile(cryptors, name):
    #read file
    try:
        infile = open(name, "r")
        cipherText = infile.read()
        #decrypt cipher text
        plainText = cryptors[1].decrypt(cipherText)
        infile.close()
    except:
        return("\n[!] Could not find file. Please provide full path and correct file type (example:/root/Documents/test.txt)")
    #unpad plain text
    while (plainText[-1] == "0"):
        plainText = plainText[:-1]
    #write plain text
    outfile = open(name, "w")
    outfile.write(plainText)
    outfile.close()
    return("\n[*] Done decrypting file")

def encryptFile(cryptors, name):
    #read file
    try:
        infile = open(name, "r")
        plainText = infile.read()
        infile.close()
    except:
        return("\n[!] Could not find file. Please provide full path and correct file type (example:/root/Documents/test.txt)")
    #pad plain text
    while (len(plainText)%16 != 0):
        plainText += "0"
    #encrypt plain text
    cipherText = cryptors[0].encrypt(plainText)
    #write cipher text
    outfile = open(name, "w")
    outfile.write(cipherText)
    outfile.close()
    return("\n[*] Done encrypting file")

#********MAIN********

running = True
while running:

    choice = raw_input("\nEncrypt or Decrypt?\n>>> ").lower()
    
    if (choice == "encrypt"):
        name = raw_input("\nWhat is the name of the file?\n>>> ")
        cryptors = setupEncryption()
        print(encryptFile(cryptors, name))
    
    elif (choice == "decrypt"):
        name = raw_input("\nWhat is the name of the file\n>>> ")
        cryptors = setupEncryption()
        print(decryptFile(cryptors, name))
    
    elif (choice == "exit"):
        running = False

    else:
        print("\n[!] Unknown command...")
