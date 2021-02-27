import socket
from my_crypt import gen_save_key, get_key, encrypt_AES, decrypt_AES, socket_send, socket_recv, decrypt_RSA, encrypt_RSA, get_signature, check_signature, BLOCK_SIZE
from Crypto.PublicKey import RSA

HOST = 'localhost'                 
PORT = 8890   

gen_save_key('pg')
publickey_pg, privatekey_pg = get_key('pg')

    
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        publickey_merchant = get_key('merchant')[0]
        ciphertext = socket_recv(conn)

        session_key = decrypt_RSA(ciphertext[:BLOCK_SIZE], privatekey_pg)
        message = decrypt_AES(ciphertext[BLOCK_SIZE:], session_key)

        PM = message[:message.find(b'sign:')]
        signature = message[message.find(b'sign:') + len(b'sign:'):]
        print(signature)

        PM_session_key = decrypt_RSA(PM[:BLOCK_SIZE], privatekey_pg)
        PM_content = decrypt_AES(PM[BLOCK_SIZE:], PM_session_key)
        
        PM_content = PM_content.split(b' ', 7)
        sid, amount, NC = PM_content[3:6]

        print(PM_content)                                   																									 # CardN, CardExp, CCode, session_id, Amount, NC, M, publickey_client
        																																						# -----BEGIN RSA PUBLIC KEY-----\n KEY CONTENT \n-----END RSA PUBLIC KEY-----\
        sign_PL_start = PM_content[7].find(b'-----END RSA PUBLIC KEY-----') + len('-----END RSA PUBLIC KEY-----') 													# should add one more signature verification
        publickey_client = PM_content[7][:sign_PL_start]
        # client_sign = PM_content[7][sign_PL_start:]

        PL = (b' '.join(PM_content[:7])) + b' ' + publickey_client

       
        try:
        	check_signature(publickey_merchant, b' '.join([sid, amount, publickey_client]), signature)
        except(ValueError) as e:
        	print(e)
        else:	
        	publickey_client = RSA.importKey(publickey_client)

        	Resp = b'0'
        	signature = get_signature(b' '.join([Resp, sid, amount, NC]), privatekey_pg)
        	ciphertext, session_key = encrypt_AES(b' '.join([Resp, sid, signature]))
        	cipherkey = encrypt_RSA(session_key, publickey_merchant)

        	socket_send(conn, cipherkey + ciphertext)