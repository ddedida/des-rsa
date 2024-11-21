import socket
import json
from rsa import encrypt_rsa

# Key PKA
e_pka = 17
n_pka = 3233
d_pka = 2753

# Key Alice & Bob
e_alice = 543059
n_alice = 730801
e_bob = 2123
n_bob = 118403

def pka_server():
    host = socket.gethostname()
    port = 5000

    server_socket = socket.socket()
    server_socket.bind((host, port))

    server_socket.listen(2)
    print(f"server PKA berjalan di {host}:{port}")

    while True:
        conn, address = server_socket.accept()
        print(f"menerima koneksi dari {address}")

        while True:
            data = conn.recv(1024).decode("utf-8")
            if not data:
                break
            if data == "alice":
                print("koneksi dari alice")

                # Signature e_bob & n_bob
                signature_e_bob = str(encrypt_rsa(str(e_bob), d_pka, n_pka))
                signature_n_bob = str(encrypt_rsa(str(n_bob), d_pka, n_pka))

                # Encryption n_bob
                encrypted_e_bob = encrypt_rsa(signature_e_bob, e_alice, n_alice)
                encrypted_n_bob = encrypt_rsa(signature_n_bob, e_alice, n_alice)
                
                message = json.dumps([encrypted_e_bob, encrypted_n_bob])
                conn.send(message.encode("utf-8"))

                print("mengirimkan public key bob ke alice")
            elif data == "bob":
                print("koneksi dari bob")

                # Signature e_alice & n_alice
                signature_e_alice = str(encrypt_rsa(str(e_alice), d_pka, n_pka))
                signature_n_alice = str(encrypt_rsa(str(n_alice), d_pka, n_pka))

                # Encryption n_alice
                encrypted_e_alice = encrypt_rsa(signature_e_alice, e_bob, n_bob)
                encrypted_n_alice = encrypt_rsa(signature_n_alice, e_bob, n_bob)

                message = json.dumps([encrypted_e_alice, encrypted_n_alice])
                conn.send(message.encode("utf-8"))
            else:
                break
        
        conn.close()

if __name__ == "__main__":
    pka_server()