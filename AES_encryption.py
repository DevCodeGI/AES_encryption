import os, sys, fnmatch
from os import listdir
from getpass import getpass
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def hashpass(password):
    hash = SHA256.new(password.encode())
    return hash.digest()


def pad(s):
    return s + b"\01234" * (AES.block_size - len(s) % AES.block_size)


def encrypt(data, hash_key, key_size=256):
    data = pad(data)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(hash_key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(data)


def decrypt(data, hash_key):
    iv = data[:AES.block_size]
    cipher = AES.new(hash_key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(data[AES.block_size:])
    return plaintext.rstrip(b"\01234")


def encrypt_file(file_name, hash_key):
    try:
        with open(file_name, 'rb') as f:
            plaintext = f.read()
        encode_data = encrypt(plaintext, hash_key)
        with open(file_name + ".enc", 'wb') as f:
            f.write(encode_data)
    except:
        return False
    return True


def decrypt_file(file_name, hash_key):
    try:
        with open(file_name, 'rb') as f:
            ciphertext = f.read()  
        decode_data = decrypt(ciphertext, hash_key)
        with open(file_name[:-4], 'wb') as f:
            f.write(decode_data)
    except:
        return False
    return True


def main():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    
    choice = input("*** File Encryption Menu ***"
                   + "\n(1) Encrypt file\n(2) Decrypt file\n"
                   + "Please choice => ")
    
    if choice == "1":
        files = fnmatch.filter(os.listdir(dir_path), "*[!.enc]")
        
        while True:
            print()
            n = 0
            print ("*** List of file(s) ***")
            for f in files:
                n += 1
                print (f"({n}) {f}")
            choice = input("Please choice => ")
            try:
                choice = int(choice)          
                if choice <= 0 or choice > len(files):
                    raise Exception()  
            except:
                print ("Error! Invalid choice, please retry...")
                continue
            file_name = files[int(choice)-1]
            break
    
        print()
        password = getpass("Enter the password: ")
        confirm_password = getpass("Confirm the password: ")
        if password != confirm_password:
            print ("Error! password does not match, aborting...")
    
        if encrypt_file(file_name, hashpass(password)):
            print()
            print (f"File encrypted to {file_name}.enc")
        else:
            print()
            print (f"File encrypt failed, aborting...")
        
    elif choice == "2":
        files = fnmatch.filter(os.listdir(dir_path), "*.enc")
        
        while True:
            print()
            n = 0
            print ("*** List of encrypted file(s) ***")
            for f in files:
                n += 1
                print (f"({n}) {f}")
            choice = input("Please choice => ")
            try:
                choice = int(choice)          
                if choice <= 0 or choice > len(files):
                    raise Exception()  
            except:
                print ("Error! Invalid choice, please retry...")
                continue
            file_name = files[int(choice)-1]
            break
    
        print()
        password = getpass("Enter the password: ")
    
        if decrypt_file(file_name, hashpass(password)):
            print()
            print (f"File decrypted to {file_name[:-4]}")
        else:
            print()
            print (f"File decrypt failed, aborting...")

    
if __name__ == "__main__":
    main()
    