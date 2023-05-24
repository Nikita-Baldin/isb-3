import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging

logger = logging.getLogger()
logger.setLevel('INFO')


def generate_symmetric_key(len: int) -> str:
    key = os.urandom(int(len/8))
    logging.info(
        ' Сгенерирован ключ для симметричного шифрования')
    return key


def encrypt_symmetric(key: bytes, text: bytes, len: int) -> bytes:
    padder = padding.ANSIX923(len).padder()
    padded_text = padder.update(text) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_text) + encryptor.finalize()
    logging.info(
        ' Текст зашифрован алгоритмом симметричного шифрования Camellia')
    return iv + cipher_text


def decrypt_symmetric(key: bytes, cipher_text: bytes, len: int) -> bytes:
    cipher_text, iv = cipher_text[16:], cipher_text[:16]
    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    text = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.ANSIX923(len).unpadder()
    unpadded_text = unpadder.update(text) + unpadder.finalize()
    logging.info(' Текст, зашифрованный алгоритмом симметричного шифрования Camellia, расшифрован')
    return unpadded_text