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
#       - plain_hex             (plain text in hex)
#       - cipher                (cipher text)
#       - key                   (key to encrypt/decrypt)
#
# List of methods :
#       - add_plain             (initialize the plain text)
#       - add_cipher            (initialize the cipher text)
#       - add_key               (initialize the key)
#       - encrypt               (encrypt the message)
#       - decrypt               (decrypt the message)
#       - display               (pretty display of the input)

from tinyRSA_key import TinyRSA_key as RSAkey

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
        self.plain_bin = None   # useful ?
        self.cipher = None
        self.key = RSAkey()     # creates an empty RSA key

    def display(self, show_key=False):
        """
        This method displays the attributes of the class
        """
        print("plain text = {}\n".format(self.plain))
        print("plain bin = {}\n".format(self.plain_bin))
        print("cipher text = {}\n".format(self.cipher))
        self.key.display()
        print("")

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
        # self.plain_hex = binascii.hexlify(self.plain.encode('utf-8')).decode()   # set the plain text in hex
        # self.plain_hex = self.plain.encode('utf-8').hex()   # byte string with the hexcodes
        self.plain_bin = ''.join('{:08b}'.format(ord(c)) for c in self.plain)

    def add_cipher(self, cipher):
        """
        This method allows to add a cipher text from a binary string (string of 0 and 1)
        This cipher text is intended to be decrypted
        """
        try:                        # make sure the cipher input is a valid binary string
            int(cipher, 2)
        except:
            raise ValueError("Invalut input for add_cipher, expected a string of 0 and 1 (example '0110100001100101011011000110110001101111' for hello).")
        self.cipher = cipher        # set the attribute

    def add_key(self, key):
        """
        This method will link a key to the message.
        This key will be used to encrypt and decrypt, it can be changed by calling this same method again with a different key.
        """
        if not isinstance(key, RSAkey):     # check if the input is a valid key
            raise ValueError("Invalid input for add_key, expected a TinyRSA_key object.")
        self.key = key                      # set the attribute

    def encrypt(self):
        """
        This method will encrypt the plain text with the key and put the result in he cipher attribute.
        """
        bit_length = self.key.get_bitlength()   # get the bitlength of the key
        if bit_length==None:                    # if it is None then the key is not set
            print("Couldn't encrypt, the key is empty.")
        else:
            blocks = [self.plain_bin[i:i+bit_length] for i in range(0, len(self.plain_bin), bit_length)]    # split the message in blocks of size bit_length
            blocks[-1] = blocks[-1] + '0'*(bit_length-len(blocks[-1]))    # pad the message to have only blocks of length bit_length. We need to pad to the right to keep the message contiguous

            # this next line executes the encryption on each block in multiple steps :
            #           convert binary to an integer
            #           perform the modular exponentiation
            #           format the result in binary
            #           pad with leading zeros up to bit_length
            self.cipher = ''.join(["{:b}".format(pow(int(blocks[i], 2), self.key.e, self.key.n)).zfill(bit_length) for i in range(len(blocks))])

    def decrypt(self):
        """
        This method will decrypt the cipher text with the key and put the result in he plain_bin attribute then update the plain
        """
        bit_length = self.key.get_bitlength()   # get the bitlength of the key
        if bit_length==None:                    # if it is None then the key is not set
            print("Couldn't decrypt, the key is empty.")
        else:
            blocks = [self.cipher[i:i+bit_length] for i in range(0, len(self.cipher), bit_length)]    # split the message in blocks of size bit_length
            blocks[-1] = blocks[-1] + '0'*(bit_length-len(blocks[-1]))  # pad the message to have only blocks of length bit_length

            # this next line executes the encryption on each block in multiple steps :
            #           convert binary to an integer
            #           perform the modular exponentiation
            #           format the result in binary
            #           pad with leading zeros up to bit_length
            self.plain_bin = ''.join(["{:b}".format(pow(int(blocks[i], 2), self.key.d, self.key.n)).zfill(bit_length) for i in range(len(blocks))])

            plains = [self.plain_bin[i:i+8] for i in range(0, len(self.plain_bin), 8)]
            plains[-1] = plains[-1] + '0'*(8-len(plains[-1]))
            self.plain = ''.join([chr(int(plains[i], 2)) for i in range(len(plains))])

if __name__ == "__main__":
    msg = RSA_message()
    msg.add_plain("Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.")

    key = RSAkey()
    key.create_new(1024)
    
    # msg.add_cipher("00100110101011110000001100100000")
    # key.create_from(60223, 50047, 5)

    msg.add_key(key)
    # msg.display()

    msg.encrypt()
    msg.display()

    msg.decrypt()
    msg.display()
