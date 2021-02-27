import socket
from my_crypt import gen_save_key, get_key, encrypt_AES, decrypt_AES, encrypt_RSA, decrypt_RSA, check_signature, get_signature, socket_send, socket_recv, BLOCK_SIZE
import json

HOST = 'localhost'
PORT = 8889

gen_save_key('client')
publickey_client, privatekey_client = get_key('client')

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

publickey_pg = get_key('pg')[0]
publickey_merchant = get_key('merchant')[0]

print('connected to' , PORT)

ciphertext, session_key = encrypt_AES(publickey_client.exportKey('PEM'))				
ciphertext_rsa = encrypt_RSA(session_key, publickey_merchant)

print(publickey_client.exportKey('PEM'))

socket_send(s, ciphertext_rsa + ciphertext)

ciphertext = socket_recv(s)

session_key = decrypt_RSA(ciphertext[:BLOCK_SIZE], privatekey_client)
message = decrypt_AES(ciphertext[BLOCK_SIZE:], session_key)

session_id = -1
print(message)

try:
	check_signature(publickey_merchant, message[:message.find(b' ')], message[message.find(b' ') + 1:])	# signature is separated from content by space
except(ValueError):
	print('Signature not verifed')
else:
	print('signature verifed')


	session_id = message[:message.find(b' ')]
	CardN = '0000000000000000'.encode()
	CardExp = '03/22'.encode()
	CCode = '000'.encode()
	Amount = '19999999999999999999999'.encode()
	NC = 'someinfo99999999999999999'.encode()
	M = 'merchantID'.encode()
	OrderDesc = 'description:999999999999999999'.encode()

	PL = b' '.join([CardN, CardExp, CCode, session_id, Amount, NC, M, publickey_client.exportKey('PEM')])
	PO = b' '.join([OrderDesc,session_id, Amount, NC])
	PM = PL + get_signature(PL, privatekey_client)
	PO_sign = get_signature(PO, privatekey_client)

	print(PO, PO_sign)
	cipher_pm, session_key = encrypt_AES(PM)

	cipher_pm_aes_key = encrypt_RSA(session_key, publickey_pg)

	cipher_pm = cipher_pm_aes_key + cipher_pm

	pm_po_cipher, session_key = encrypt_AES(cipher_pm + PO + b' ' + PO_sign)
	pm_po_aes_key = encrypt_RSA(session_key, publickey_merchant)

	socket_send(s, pm_po_aes_key + pm_po_cipher)

	ciphertext = socket_recv(s)

	session_key = decrypt_RSA(ciphertext[:BLOCK_SIZE], privatekey_client)
	message = decrypt_AES(ciphertext[BLOCK_SIZE:], session_key)

	message = message.split(b' ', 2)
	Resp = message[0]
	print(message)


	try:
		check_signature(publickey_pg, b' '.join([Resp, session_id, Amount, NC]), message[2])		
	except(ValueError) as e:
		print(e)
	else:
		print(Resp)
		print('done')

s.close()