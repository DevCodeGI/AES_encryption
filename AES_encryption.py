import os, sys, fnmatch, traceback
from os import listdir
from getpass import getpass
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def genkey(password):
    hash = SHA256.new(password.encode())
    return hash.digest()


def encrypt(data, pass_key):
    data = pad(data, AES.block_size, style='pkcs7')
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(pass_key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(data)


def decrypt(data, pass_key):
    iv = data[:AES.block_size]
    cipher = AES.new(pass_key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(data[AES.block_size:])
    plaintext = unpad(plaintext, AES.block_size, style='pkcs7')
    return plaintext


def encrypt_file(file_name, pass_key):
    try:
        with open(file_name, 'rb') as f:
            plaintext = f.read()
        encode_data = encrypt(plaintext, pass_key)
        with open(file_name + '.enc', 'wb') as f:
            f.write(encode_data)
    except:
        return False
    return True


def decrypt_file(file_name, pass_key):
    try:
        with open(file_name, 'rb') as f:
            ciphertext = f.read()  
        decode_data = decrypt(ciphertext, pass_key)
        with open(file_name[:-4], 'wb') as f:
            f.write(decode_data)
    except:
        return False
    return True


def main():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    
    choice = input('*** File Encryption Menu ***'
                   + '\n(1) Encrypt file\n(2) Decrypt file\n'
                   + 'Please choice => ')
    
    if choice == '1':
        files = fnmatch.filter(os.listdir(dir_path), '*[!.enc]')
        
        while True:
            n = 0
            print ('\n*** List of file(s) ***')
            for f in files:
                n += 1
                print (f'({n}) {f}')
            choice = input('Please choice => ')
            try:
                choice = int(choice)          
                if choice <= 0 or choice > len(files):
                    raise Exception()  
            except:
                print ('Error! Invalid choice, please retry...')
                continue
            file_name = files[int(choice)-1]
            break
    
        while True:    
            password = getpass('\nEnter the password: ')
            confirm_password = getpass('Confirm the password: ')
            if password != confirm_password:
                print ('Error! password does not match. Aborting...')
                continue              
            break
            
        print ('\nProcessing...', end='')
    
        if encrypt_file(file_name, genkey(password)):
            print (f'done, file encrypted to "{file_name}.enc"')
        else:
            print (f'error, encryption failed. Aborting...')
        
    elif choice == '2':
        files = fnmatch.filter(os.listdir(dir_path), '*.enc')
        
        while True:
            n = 0
            print ('\n*** List of encrypted file(s) ***')
            for f in files:
                n += 1
                print (f'({n}) {f}')
            choice = input('Please choice => ')
            try:
                choice = int(choice)          
                if choice <= 0 or choice > len(files):
                    raise Exception()  
            except:
                print ('Error! Invalid choice, please retry...')
                continue
            file_name = files[int(choice)-1]
            break
    
        password = getpass('\nEnter the password: ')
        
        print ('\nProcessing...', end='')
    
        if decrypt_file(file_name, genkey(password)):
            print (f'done, file decrypted to "{file_name[:-4]}"')
        else:
            print (f'error, decryption failed. Aborting...')

    
if __name__ == '__main__':
    main()

