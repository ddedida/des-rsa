import socket, json, ast
from rsa import encrypt_rsa, decrypt_rsa
from table import keyp, shift_table, key_comp
from util import hex_to_bin, bin_to_hex, left_shift, permutation, decrypt_ecb, bin_to_dec

# Key Bob
e_bob = 2123
d_bob = 77171
n_bob = 118403

# Key PKA
e_pka = 17
n_pka = 3233

# Key Alice
e_alice = -1
n_alice = -1

# DES Key
des_key = -1

# Get Public Key Alice from PKA
def get_public_key_alice(message_id):
    host = socket.gethostname()
    port = 5000

    bob_socket = socket.socket()
    bob_socket.connect((host, port))
    bob_socket.send(message_id.encode("utf-8"))

    message = bob_socket.recv(1024).decode("utf-8")
    encrypted_e_alice, encrypted_n_alice = json.loads(message)

    bob_socket.close()

    # Decrypt Signature
    decrypted_signature_e_alice = ast.literal_eval(decrypt_rsa(encrypted_e_alice, d_bob, n_bob))
    decrypted_signature_n_alice = ast.literal_eval(decrypt_rsa(encrypted_n_alice, d_bob, n_bob))

    # Decrypt Public Key Alice
    decrypted_e_alice = decrypt_rsa(decrypted_signature_e_alice, e_pka, n_pka)
    decrypted_n_alice = decrypt_rsa(decrypted_signature_n_alice, e_pka, n_pka)

    return int(decrypted_e_alice), int(decrypted_n_alice)

# Public Key Cryptosystem for Bob
def bob_server():
    host = socket.gethostname()
    port = 6000

    bob_socket = socket.socket()
    bob_socket.bind((host, port))

    bob_socket.listen(2)
    print(f"server Bob berjalan di {host}:{port}")

    # Accept Alice connection
    conn, address = bob_socket.accept()
    print(f"menerima koneksi dari {address}")

    # Get the message from Alice
    data = json.loads(conn.recv(1024).decode("utf-8"))
    data_id = data["id"]
    encrypted_nonce_1 = data["nonce"]

    # Get Public Key Alice
    e_alice, n_alice = get_public_key_alice("bob")
    print(f"public key alice: e={e_alice}, n={n_alice}")

    # Decrypt nonce 1
    decrypted_nonce_1_signature = ast.literal_eval(decrypt_rsa(encrypted_nonce_1, d_bob, n_bob))
    decrypted_nonce_1_str = decrypt_rsa(decrypted_nonce_1_signature, e_alice, n_alice)

    print(f"message_id: {data_id}, nonce: {decrypted_nonce_1_str}")

    # Encrypt nonce 2 and send to Alice
    nonce_2 = "67890"
    signature_nonce_2 = str(encrypt_rsa(nonce_2, d_bob, n_bob))
    encrypted_nonce_2 = encrypt_rsa(signature_nonce_2, e_alice, n_alice)
    message = {
        "id": "bob",
        "nonce_1": decrypted_nonce_1_str,
        "nonce_2": encrypted_nonce_2
    }
    conn.send(json.dumps(message).encode("utf-8"))

    # Get response nonce 2 from Alice
    response = json.loads(conn.recv(1024).decode("utf-8"))
    nonce_2_from_alice = response["nonce_2"]
    if nonce_2_from_alice == nonce_2:
        print("Alice is verified\n")
    else:
        print("Not Alice\n")
    
    # Tell Alice that Bob is ready
    conn.send("Bob is ready".encode("utf-8"))

    # ===== KEY EXCHANGE =====e
    print("===== KEY EXCHANGE =====")
    # Get DES Key from Alice
    response = json.loads(conn.recv(1024).decode("utf-8"))
    encrypted_des_key = response["des_key"]

    # Decrypt DES Key
    decrypted_des_key_signature = ast.literal_eval(decrypt_rsa(encrypted_des_key, d_bob, n_bob))
    des_key = decrypt_rsa(decrypted_des_key_signature, e_alice, n_alice)

    print(f"DES Key: {des_key}\n")

    # ===== DES ALGORITHM =====

    while True:
        data = conn.recv(1024).decode()
        if not data:
            break
        key = des_key

        if(len(data) % 16 != 0):
            chiper_text = data[:-1]
        else:
            chiper_text = data

        print(f"-> chiper text: {chiper_text}")
        print(f"key: {key}")

        # KEY PROCESS
        key = hex_to_bin(key)
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

        rk_rev = rk[::-1]
        rkb_rev = rkb[::-1]

        plain_text = bin_to_hex(decrypt_ecb(chiper_text, rkb_rev, rk_rev))

        if(len(data) % 16 != 0):
            padding_len = bin_to_dec(int(hex_to_bin(data[-1])))
            plain_text = plain_text[:-padding_len]
            print(f"plain text: {plain_text}")
        else:
            print(f"plain text: {plain_text}")

    bob_socket.close()

if __name__ == "__main__":
    bob_server()