import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging

logger = logging.getLogger()
logger.setLevel('INFO')


def generate_symmetric_key(len: int) -> str:
    """
    Функция генерирует ключ для симметричного шифрования
    :param len: длина ключа
    :return: ключ 
    """
    if len == 128 or len == 192 or len == 256:
        key = os.urandom(int(len/8))
        logging.info(
            ' Сгенерирован ключ для симметричного шифрования')
    else:
        logging.info(
            ' Длина ключа не равна 128, 192, 256')
    return key


def encrypt_symmetric(key: bytes, text: bytes, len: int) -> bytes:
    """
    Функция шифрует текст алгоритмом симметричного шифрования Camellia
    :param len: длина ключа
    :param text: текст, который шифруем
    :param key: ключ
    :return: зашифрованный текст
    """
    try:
        padder = padding.ANSIX923(len).padder()
        padded_text = padder.update(text) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_text) + encryptor.finalize()
        logging.info(f' Текст зашифрован алгоритмом симметричного шифрования Camellia')
    except OSError as err:
        logging.warning(f' Ошибка при симметричном шифровании {err}')
    return iv + cipher_text


def decrypt_symmetric(key: bytes, cipher_text: bytes, len: int) -> bytes:
    """
    Функция расшифровывает симметрично зашифрованный текст
    :param len: длина ключа
    :param cipher_text: зашифрованный текст
    :param key: ключ
    :return: возвращает расшифрованный текст
    """
    try:
        cipher_text, iv = cipher_text[16:], cipher_text[:16]
        cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        text = decryptor.update(cipher_text) + decryptor.finalize()
        unpadder = padding.ANSIX923(len).unpadder()
        unpadded_text = unpadder.update(text) + unpadder.finalize()
        logging.info(f' Текст, зашифрованный алгоритмом симметричного шифрования Camellia, расшифрован')
    except OSError as err:
        logging.warning(f' Ошибка при симметричном дешифровании {err}')
    return unpadded_text