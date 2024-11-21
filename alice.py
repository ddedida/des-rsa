import socket, json, ast
from rsa import encrypt_rsa, decrypt_rsa
from table import keyp, shift_table, key_comp
from util import hex_to_bin, bin_to_hex, left_shift, permutation, encrypt_ecb

# Key Alice
e_alice = 543059
d_alice = 251963
n_alice = 730801

# Key PKA
e_pka = 17
n_pka = 3233

# Key Bob
e_bob = -1
n_bob = -1

# DES Key
des_key = "AABBCCDDEEFF1122"

# Get Public Key Bob from PKA
def get_public_key_bob(message_id):
    host = socket.gethostname()
    port = 5000

    alice_socket = socket.socket()
    alice_socket.connect((host, port))
    alice_socket.send(message_id.encode("utf-8"))

    message = alice_socket.recv(1024).decode("utf-8")
    encrypted_e_bob, encrypted_n_bob = json.loads(message)
    
    alice_socket.close()

    # Decrypt Signature
    decrypted_signature_e_bob = ast.literal_eval(decrypt_rsa(encrypted_e_bob, d_alice, n_alice))
    decrypted_signature_n_bob = ast.literal_eval(decrypt_rsa(encrypted_n_bob, d_alice, n_alice))

    # Decrypt Public Key Bob
    decrypted_e_bob = decrypt_rsa(decrypted_signature_e_bob, e_pka, n_pka)
    decrypted_n_bob = decrypt_rsa(decrypted_signature_n_bob, e_pka, n_pka)

    return int(decrypted_e_bob), int(decrypted_n_bob)

# Public Key Cryptosystem for Alice
def alice_server():
    # Get Public Key Bob
    message_id = "alice"
    e_bob, n_bob = get_public_key_bob(message_id)
    print(f"public key bob: e={e_bob}, n={n_bob}")

    # Initial Message to Bob
    nonce_1 = "12345"
    host = socket.gethostname()
    port = 6000

    alice_socket = socket.socket()
    alice_socket.connect((host, port))

    # Encrypt nonce 1 the send to Bob
    signature_nonce_1 = str(encrypt_rsa(nonce_1, d_alice, n_alice))
    encrypted_nonce_1 = encrypt_rsa(signature_nonce_1, e_bob, n_bob)

    message = {
        "id": "alice",
        "nonce": encrypted_nonce_1
    }
    alice_socket.send(json.dumps(message).encode("utf-8"))

    # Get response from Bob
    response = json.loads(alice_socket.recv(1024).decode("utf-8"))
    nonce_1_from_bob = response["nonce_1"]
    data_id = response["id"]
    nonce_2 = response["nonce_2"]

    # Verify Bob
    if nonce_1 == nonce_1_from_bob:
        print("Bob is verified")
    else:
        print("Not Bob")
    
    # Decrypt nonce 2
    decrypted_nonce_2_signature = ast.literal_eval(decrypt_rsa(nonce_2, d_alice, n_alice))
    decrypted_nonce_2_str = decrypt_rsa(decrypted_nonce_2_signature, e_bob, n_bob)

    print(f"message_id: {data_id}, nonce: {decrypted_nonce_2_str}")

    # Send nonce 2 to Bob
    message = {
        "id": "alice",
        "nonce_2": decrypted_nonce_2_str
    }
    alice_socket.send(json.dumps(message).encode("utf-8"))

    # Get status from Bob
    status = alice_socket.recv(1024).decode("utf-8")
    if status == "Bob is ready":
        print("Ready to send key to Bob\n")

    # ===== KEY EXCHANGE =====
    print("===== KEY EXCHANGE =====")
    encrypted_des_key_signature = str(encrypt_rsa(des_key, d_alice, n_alice))
    encrypted_des_key = encrypt_rsa(encrypted_des_key_signature, e_bob, n_bob)
    message = {
        "id": "alice",
        "des_key": encrypted_des_key
    }
    alice_socket.send(json.dumps(message).encode("utf-8"))
    print("DES Key sent to Bob\n")

    # ===== DES ALGORITHM =====
    while True:
        pt = input("-> Enter plaintext: ") # 123456789ABCDEF11234
        
        if (pt != 'bye'):
            print(f"plain text: {pt}")
            print(f"key: {des_key}")

            # KEY PROCESS
            key = hex_to_bin(des_key)
            key = permutation(key, keyp, 56)
            left = key[0:28]
            right = key[28:56]
            rk = []
            rkb = []

            for i in range(0, 16):
                # Left Shift
                left = left_shift(left, shift_table[i])
                right = left_shift(right, shift_table[i])

                # Combine
                combine_str = left + right

                # Compress to 48-bit
                round_key = permutation(combine_str, key_comp, 48)

                rkb.append(round_key)
                rk.append(bin_to_hex(round_key))

            cipher_text_bin, last_char = encrypt_ecb(pt, rkb, rk)
            cipher_text = bin_to_hex(cipher_text_bin) + last_char
            
            alice_socket.send(cipher_text.encode())
        else:
            break

    alice_socket.close()

if __name__ == "__main__":
    alice_server()