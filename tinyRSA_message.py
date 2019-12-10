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
#       - tinyRSA_key           (key to encrypt/decrypt)
#
# List of methods :
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
