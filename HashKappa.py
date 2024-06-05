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

def md5_hash_string(input_string, format=False):
    # Create an MD5 hash object
    if format == 'md5':
        md5_hash = hashlib.md5()
    elif format == 'NT':
        md5_hash = hashlib.NT()
    elif format == False:
        md5_hash = hashlib.md5()
    else:
        return 'Error'
    
    # Update the hash object with the bytes of the input string
    md5_hash.update(input_string.encode('utf-8'))
    
    # Get the hexadecimal digest of the hash
    hex_digest = md5_hash.hexdigest()
    
    return hex_digest

#Compare hashes to passwords in a dump
def comparePasswordList(passwordList, hashList, format=False):
    crackedPasswords = []
    #Looping through hash list
    for i in hashList:
        #Compare md5 hash of password list to current hash
        for n in passwordList:
            #If they match, add to crackedPasswords list
            hex_digest = md5_hash_string(n, format)
            if hex_digest == i:
                crackedPasswords.append("Hash: {} is {}".format(i, n))
            elif hex_digest == 'Error':
                return 'This format is not recognised'
    #Return the cracked passwords
    return crackedPasswords

#Main file loop
def mainLoop():
    # create parser
    descStr = "This script attempts to crack a given hash dump using a given password list"
    parser = argparse.ArgumentParser(description=descStr)
    # add expected arguments
    parser.add_argument('--hash-dump', help='Required hash dump to crack', dest='hashFile', required=True)
    parser.add_argument('--password-file', help='Password file to compare against the hash dump', dest='passwordFile', required=True)
    parser.add_argument('--format', help='Hash algorithm', dest='hashFormat', required=False)
    args = parser.parse_args()

    #Passing arguments into vars
    hashFile = args.hashFile
    passwordFile = args.passwordFile
    hashFormat = args.hashFormat

    hashList = openHashFile(hashFile)
    passwordList = openPasswordFile(passwordFile)

    
    crackedPasswords = comparePasswordList(passwordList, hashList, hashFormat)
   
    if crackedPasswords == 'This format is not recognised':
        print(crackedPasswords)
    else:
        for i in crackedPasswords:
            print(i)


if __name__ == "__main__":
    mainLoop()
