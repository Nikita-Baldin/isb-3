from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import logging

logger = logging.getLogger()
logger.setLevel('INFO')


def generate_asymmetric_keys() -> tuple:
    """
    Функция генерирует ключи для асимметричного шифрования
    :return: закрытый ключ и открытый ключ
    """
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = keys
    public_key = keys.public_key()
    logging.info(' Сгенерированы ключи асимметричного шифрования')
    return private_key, public_key


def encrypt_asymmetric(public_key, text: bytes) -> bytes:
    """
    Функция производит асимметричное шифрование по открытому ключу
    :param text: текст, который шифруем
    :param public_key: открытый ключ
    :return: зашифрованный текст
    """
    try:
        encrypted_text = public_key.encrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                               algorithm=hashes.SHA256(), label=None))
        logging.info(f' Текст зашифрован алгоритмом асимметричного шифрования')
    except OSError as err:
        logging.warning(f'Ошибка при асимметричном шифровании {err}')

    return encrypted_text


def decrypt_asymmetric(private_key, text: bytes) -> bytes:
    """
    Функция расшифровывает асимметрично зашифрованный текст, с помощью закрытого ключа
    :param text: зашифрованный текст
    :param private_key: закрытый ключ
    :return: расшифрованный текст
    """
    try:
        decrypted_text = private_key.decrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                algorithm=hashes.SHA256(), label=None))
        logging.info(f' Текст, зашифрованный алгоритмом асимметричного шифрования, расшифрован')
    except OSError as err:
        logging.warning(f' Ошибка при асимметричном дешифровании {err}')
    return decrypted_text