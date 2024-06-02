import pyfiglet
import hashlib
import argparse

banner = pyfiglet.figlet_format("Hash Kappa")

print(banner)

#open hashed file function and append hashes to a list
def openHashFile(hashFile):
    hashes = []
    #Open and read lines within the provided hashFile
    with open(hashFile, 'r') as f:
        hashFile = f.readlines()
        for line in hashFile:
            hashes.append(line.strip())
        #return list of hashes
    return hashes

#Open password list and append it to a list
def openPasswordFile(passwordFile):
    passwords = []
    #Open password file and read lines
    with open(passwordFile, 'r') as f:
        passwordFile = f.readlines()
        for line in passwordFile:
            passwords.append(line.strip())
    #return the list of passwords to hash and compare
    return passwords

def md5_hash_string(input_string):
    # Create an MD5 hash object
    md5_hash = hashlib.md5()
    
    # Update the hash object with the bytes of the input string
    md5_hash.update(input_string.encode('utf-8'))
    
    # Get the hexadecimal digest of the hash
    hex_digest = md5_hash.hexdigest()
    
    return hex_digest

#Compare hashes to passwords in a dump
def comparePasswordList(passwordList, hashList):
    crackedPasswords = []
    #Looping through hash list
    for i in hashList:
        #Compare md5 hash of password list to current hash
        for n in passwordList:
            #If they match, add to crackedPasswords list
            hex_digest = md5_hash_string(n)
            if hex_digest == i:
                crackedPasswords.append("Hash: {} is {}".format(i, n))
    #Return the cracked passwords
    return crackedPasswords

#Main file loop
def mainLoop():
    # create parser
    descStr = "This script compares an MD5 hashdump against a pre-exisiting password list"
    parser = argparse.ArgumentParser(description=descStr)
    # add expected arguments
    parser.add_argument('--hash-dump', dest='hashFile', required=True)
    parser.add_argument('--password-file', dest='passwordFile', required=True)
    
    args = parser.parse_args()
    #Passing arguments into vars
    hashFile = args.hashFile
    passwordFile = args.passwordFile

    hashList = openHashFile(hashFile)
    passwordList = openPasswordFile(passwordFile)

    crackedPasswords = comparePasswordList(passwordList, hashList)
    """ print(passwordList) #Testing passwords list has been correctly added
    print(hashList) #Testing hash list has been correctly added """
    for i in crackedPasswords:
        print(i)


if __name__ == "__main__":
    mainLoop()