from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


BLOCK_SIZE = 128

def socket_recv(sd):
	len = int(sd.recv(16).decode())
	data = sd.recv(len)
	return data

def socket_send(sd, msg):
    length = len(msg)
    print('0' * (16 - len(str(length))) + str(length))
    sd.sendall(('0' * (16 - len(str(length))) + str(length)).encode())
    sd.sendall(msg)


def gen_save_key(file):
	KEY = RSA.generate(1024)
	print('generated rsa key')
	private_key = KEY.exportKey('PEM')
	file_private = open("private" + file +".pem", "wb")
	file_private.write(private_key)
	file_private.close()
	print('privated key written private' + file + '.pem')

	public_key = KEY.publickey().exportKey('PEM')
	file_public = open("public" + file +".pem", "wb")
	file_public.write(public_key)
	file_public.close()
	print('public key written public' + file + '.pem')
	
def get_key(file):
	return RSA.import_key(open("public" + file +".pem").read()), RSA.import_key(open("private" + file +".pem").read())

def encrypt_AES(message):
	aes_key = get_random_bytes(32)
	cipher = AES.new(aes_key, AES.MODE_ECB)

	return cipher.encrypt(pad(message, BLOCK_SIZE)), aes_key

def decrypt_AES(encrypted, aes_key):
	cipher = AES.new(aes_key, AES.MODE_ECB)

	return unpad(cipher.decrypt(encrypted), BLOCK_SIZE)

def encrypt_RSA(message, pub_key):
	cipher = PKCS1_OAEP.new(pub_key)
	return cipher.encrypt(message)

def decrypt_RSA(ciphertext, priv_key):
	cipher = PKCS1_OAEP.new(priv_key)
	return cipher.decrypt(ciphertext)

def get_signature(message, priv_key):
	h = SHA256.new(message)
	return pkcs1_15.new(priv_key).sign(h)

def check_signature(pub_key, message, signature):
	h = SHA256.new(message)
	pkcs1_15.new(pub_key).verify(h, signature)