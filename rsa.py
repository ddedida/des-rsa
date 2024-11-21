def encrypt_rsa(message, key, n):
    message_encoded = [ord(char) for char in message]
    encrypted = [pow(char, key, n) for char in message_encoded]
    return encrypted

def decrypt_rsa(encrypted_text, key, n):
    decrypted = [pow(char, key, n) for char in encrypted_text]
    return ''.join(chr(char) for char in decrypted)