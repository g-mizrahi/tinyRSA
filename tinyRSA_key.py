# This file is part of the TinyRSA project.
# This project is about implementing a very simple (and insecure) RSA cryptosystem to play around
# The main goal is to be able to change the length of the key for hacking purposes
#
# Guilhem Mizrahi 12/2019
#
# This file contains the class to describe an RSA key
# Everything is intentionnaly made public in this class, even the private key as the goal of TinyRSA is to see everything happening
# Do NOT use this for encryption purposes
#
# List of attributes :
#       - p                 (first prime number)
#       - q                 (second prime number)
#       - n                 (n = p*q is part of the public key)
#       - lowest_multiple   (lcm(p-1, q-1) is used to generate the private key)
#       - e                 (the public exponent, part of the public key)
#       - d                 (the private exponent, part of the private key)
#
#
# List of methods :
#       - __init__          (constructor of the class)
#       - create_new        (generating a new key)
#       - create_from       (generating a key from known values - p, q and e)
#
