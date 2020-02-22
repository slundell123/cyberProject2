"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:



"""

import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

host = "localhost"
port = 10001


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    private_key = RSA.importKey(open('client_cert').read())
    private_cipher=PKCS1_OAEP.new(private_key)
    message=private_cipher.decrypt(session_key)
    return message

#NOTE: look at -  https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
   # print(session_key)
    cipher = AES.new(session_key, AES.MODE_ECB)
    plaintext=cipher.decrypt(client_message)
    return plaintext

'''
Encryption takes a plain text and converts it to an encrypted text using a 
key and an encryption algorithm. The resulting encrypted text can later be 
decrypted (by using the same key and algorithm).
A digest takes a plain text and generates a hashcode which can be used to 
verify if the plain text is unmodified but cannot be used to decrypt the 
original text from the hash value.
'''
#from https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
# Encrypt a message using the session key
def encrypt_message(message, session_key):
    #print (session_key)
    cipher = AES.new(session_key, AES.MODE_ECB)
    #nonce = cipher.nonce #stopping replay attachs with a random number
    ciphertext= cipher.encrypt(message)
    # returning random number, encrypted message, and digest (see note
    # above function for details)
    return ciphertext


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                # TODO: Generate the hashed password
                # hashed_password =
                return hashed_password == line[2]
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)
                print("Encrypted message from client: ",ciphertext_message)
                # TODO: Decrypt message from client
                plaintext_message=decrypt_message(ciphertext_message,plaintext_key).decode() #.decode needed convert decrypted message from bytes to char
                # TODO: Split response from user into the username and password
                credentials=plaintext_message.rstrip().split(' ',1)
                print("Username: ",credentials[0]," Password: ",credentials[1]) #test decrypted username and password from the client
                # TODO: Encrypt response to client

                # Send encrypted response
               # send_message(connection, ciphertext_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
