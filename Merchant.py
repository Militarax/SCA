import socket
import random
from my_crypt import gen_save_key, get_key, encrypt_AES, decrypt_AES, encrypt_RSA, decrypt_RSA, get_signature, check_signature, socket_send, socket_recv, BLOCK_SIZE
from Crypto.PublicKey import RSA

HOST_M = 'localhost'                 
PORT_M = 8889           

HOST_PG = 'localhost'
PORT_PG = 8890

gen_save_key('merchant')
publickey_merchant, privatekey_merchant = get_key('merchant')


r = random.Random()

socket_pg = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_pg.connect((HOST_PG, PORT_PG))
publickey_pg = get_key('pg')[0]

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
	print('server started at ' + str(PORT_M))	
	server.bind((HOST_M, PORT_M))
	server.listen(1)
	conn, addr = server.accept()
	session_id = r.randint(0,1000)
	with conn:

		print('Connected by', addr)
		ciphertext = socket_recv(conn)
		
		session_key = decrypt_RSA(ciphertext[:BLOCK_SIZE], privatekey_merchant)
		publickey_client = RSA.importKey(decrypt_AES(ciphertext[BLOCK_SIZE:], session_key))
		print(publickey_client)
		
		message = str(session_id).encode()
		message = message + b' ' + get_signature(message, privatekey_merchant)
		print(message)
		cipher, session_key = encrypt_AES(message)
		cipher_key = encrypt_RSA(session_key, publickey_client)

		socket_send(conn,cipher_key + cipher)


		ciphertext = socket_recv(conn)

		session_key = decrypt_RSA(ciphertext[:BLOCK_SIZE], privatekey_merchant)
		pm_po = decrypt_AES(ciphertext[BLOCK_SIZE:], session_key)
		PO = pm_po[pm_po.find(b'description:'):]										# {PM,PO}pubkM
		PM = pm_po[:pm_po.find(b'description:')]										# {PM, OrderDesc,session_id, Amount, NC}
		
		PO = PO.split(b' ', 4)
		print(PO)
		signature = PO[4]

		try: 
			check_signature(publickey_client, b' '.join(PO[:4]), signature)
		except(ValueError) as e:
			print(e)
		else:
			print('signature PO verified')
			sid, amount, NC = PO[1], PO[2], PO[3]


			print(b' '.join([sid, amount, publickey_client.exportKey('PEM')]))
			signature = get_signature(b' '.join([sid, amount, publickey_client.exportKey('PEM')]), privatekey_merchant)

			message = PM + b'sign:' + signature 										# here PM content is separated from signature by 'sign:'. Pm content can have more spaces than meant to be (RSA key)
			print(message)
			ciphertext, session_key = encrypt_AES(message)
			cipher_key = encrypt_RSA(session_key, publickey_pg)
			
			socket_send(socket_pg, cipher_key + ciphertext)

			ciphertext = socket_recv(socket_pg)

			session_key = decrypt_RSA(ciphertext[:BLOCK_SIZE], privatekey_merchant)
			mess = decrypt_AES(ciphertext[BLOCK_SIZE:], session_key)



			socket_pg.close()

			timeout = True
			if timeout:
				ciphertext, session_key = encrypt_AES(mess)
				length = str(len(ciphertext)).encode()
				cipher_key = encrypt_RSA(session_key, publickey_client)

				socket_send(conn, cipher_key + ciphertext)


