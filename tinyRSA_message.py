# This file is part of the TinyRSA project.
# This project is about implementing a very simple (and insecure) RSA cryptosystem to play around
# The main goal is to be able to change the length of the key for hacking purposes
#
# Guilhem Mizrahi 12/2019
#
# This file contains the class to describe a message
# It is intended to be used with the tinyRSA_key class to be encrypted and decrypted
#
# List of attributes :
#       - plain                 (plain text)
#       - plain_hex             (plain text in hex) - useful ?
#       - plain_bin             (plain text in binary) - useful ?
#       - cipher                (cipher text)
#       - cipher_hex            (cipher text in hex) - useful ?
#       - cipher_bin            (cipher text in binary) - useful ?
#       - key                   (key to encrypt/decrypt)
#
# List of methods :
#       - add_plain             (initialize the plain text)
#       - add_cipher            (initialize the cipher text)
#       - add_key               (initialize the key)
#       - pad                   (break the message into blocks and pad it)
#       - crypt_block           (perform the encrypt/decrypt operation on a single block)
#       - encrypt               (encrypt the message)
#       - decrypt               (decrypt the message)
#       - encode_message        (encode the message)
#       - decode_message        (decode the message)
#       - ascii_to_hex          (convert a string into hex codes)
#       - hex_to_ascii          (convert the hex codes into a string)
#       - display               (pretty display of the input)
#       - renew_key             (generate/create a new RSA key to encrypt/decrypt)

from tinyRSA_key import TinyRSA_key as RSAkey
import binascii

class RSA_message():
    """
    This class describes a message fitting for the TinyRSA project.
    Everything is public even private keys as the goal is not to do encryption but to pay around with the RSA scheme.
    """

    def __init__(self):
        """
        The constructor is just to create the class attributes, the plain or cipher texts and the key have to be added with the add_plain, add_cipher and add_key methods.
        """
        self.plain = None
        self.plain_hex = None
        self.cipher = None
        self.key = RSAkey()     # creates an empty RSA key

    def display(self, show_key=False):
        """
        This method displays the attributes of the class
        """
        print("\tplain text = {}".format(self.plain))
        print("\tplain hex = {}".format(self.plain_hex))
        print("\tcipher text = {}".format(self.cipher))
        self.key.display()

    def add_plain(self, plain):
        """
        This method allows to add a plain text to the message
        This message is intended to be encrypted
        """
        try:                        # make sure the plain text is a string
            plain = str(plain)
        except:
            raise ValueError("Invalid input for add_plain. Couldn't convert message to str.")

        self.plain = plain          # set the plain text
        self.plain_hex = binascii.hexlify(self.plain.encode('utf-8'))   # set the plein text in hex

    def add_cipher(self, cipher):
        """
        This method allows to add a cipher text from a hex string
        This cipher text is intended to be decrypted
        """
        try:                        # make sure the cipher input is a valid hexstring
            cipher = binascii.unhexlify(cipher)
        except:
            raise ValueError("Invalut input for add_cipher, expected a byte string of hexcodes (example b'68656c6c6f' for hello).")
        self.cipher = cipher        # set the attribute

    def add_key(self, key):
        """
        This method will link a key to the message.
        This key will be used to encrypt and decrypt, it can be changed by calling this same method again with a different key.
        """
        if not isinstance(key, RSAkey):    # check if the input is a valid key
            raise ValueError("Invalid input for add_key, expected a TinyRSA_key object.")
        self.key = key

if __name__ == '__main__':
    msg = RSA_message()
    msg.add_plain("hello")
    msg.add_cipher(b"68656c6c6f68656c6c6f")
    msg.display()
    key = RSAkey()
    key.create_new()
    msg.add_key(key)
