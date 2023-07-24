from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad


def encrypt_data(key, data):
  iv = get_random_bytes(AES.block_size)

  cipher = AES.new(key, AES.MODE_CBC, iv)

  padded_data = pad(data.encode('utf-8'), AES.block_size)

  ciphertext = iv + cipher.encrypt(padded_data)

  return ciphertext


def decrypt_data(key, ciphertext):
  iv = ciphertext[:AES.block_size]

  cipher = AES.new(key, AES.MODE_CBC, iv)

  decrypted_data = unpad(cipher.decrypt(ciphertext[AES.block_size:]),
                         AES.block_size)

  return decrypted_data.decode('utf-8')


if __name__ == "__main__":
  encryption_key = b'ThisIsASecretKey'

  original_data = "Hello, this is a test message!"

  # Encrypt the data
  encrypted_data = encrypt_data(encryption_key, original_data)
  print("Encrypted:", encrypted_data.hex())

  # Decrypt the data
  decrypted_data = decrypt_data(encryption_key, encrypted_data)
  print("Decrypted:", decrypted_data)
