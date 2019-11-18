# Implement the RSA encryption and decryption algorithms
# TO DO Implement a crack of the algorithm for small numbers

# Guilhem Mizrahi 11/2019

# RSA algorithm
# 4 steps :
#       - Key generation
#       - Key distribution
#       - Key encryption
#       - Key decryption
# refer to https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29

# TO DO
# Backend
#       - integrate into webapp
#       - encode ascii to hex to display in HTML
#       - decode hex to ascii to decode from HTML and into binary with encode_message
# Frontend
#       - better looking page : minimalist design
#       - better display of keys and text
#       - possibility to select the value of the bit length of keys
#       - better explanation of process

# With 1024 bits long primes (2048 bits RSA key) it takes between 1.5 and 7 seconds
# Almost 100% of that time is spent generating the prime numbers

# import math # only needed for the sqrt function in the slow primality test
import random
import time

def is_number(n):
    '''
    Returns True if the input is an integer
    '''
    return(isinstance(n, int))

# def is_prime_slow(n):
#     '''
#     Test if a number is prime. Return True if it is and False otherwise
#     Using the most simple method of checking all numbers up to the square root
#     Complexity is O(sqrt(n))
#     '''
#     if not is_number(n) or n<2:
#         return(False)
#     else:
#         limit=math.ceil(math.sqrt(n))
#         for i in range(2, limit+1):
#             if n%i==0:
#                 return(False)
#         return(True)

def is_prime_fast(n):
    '''
    Check if a number is likely to be prime using the Miller-Rabin primality check in a single pass. To have more accuracy, the program would have to have to perform multiple passes

    Complexity is in log2(n) for a single pass.
    Depending on how many passes we want to implement the complexity is likely to change

    For more information refer to
    https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    '''
    if not is_number(n) or n<2:
        return(False)
    else:
        # we want to decompose n=d*2^s+1 with d odd
        s=0
        while (n-1)%pow(2, s+1)==0: # we want to check for the max value of r
            s+=1
        d=(n-1)//pow(2, s)          # d is obtained by a simple division
        a=random.randint(2, n-1)    # if n is prime then a^d=1(mod n) or a^(d*2^r)=-1(mod n) for some 0<=r<=s-1
                                    # if we can verify this for all values of a then n is likely to be prime (but not necessarily)
        witness=pow(a, d, n)
        if (witness==1 or witness==n-1):
            return(True)            # The probability that n is prime is reasonable
                                    # n is not necessarily prime though
                                    # to increase the probability we should go though this check for multiple values of a
        else:
            for j in range(s-1):    # we have to check if a^(d*2^r)=-1(mod n) for some 0<=r<=s-1 (in which case n is probably prime)
                witness=pow(witness, 2, n)
                if (witness==n-1):
                    return(True)
            return(False)           # otherwise we know for sure that n is composite
            # If it never got out of the loop then it mean that it never found a root in the Z/nZ among the possible witnesses so we return False

def choose_prime(l):
    '''
    Will return a random prime of bit length l
    This function implements a monte carlo method of finding prime numbers.
    By choosing random numbers until it has found a prime
    '''
    assert is_number(l) and l>0, "Invalid bitlength"

    count_passes=0
    start=pow(2,l-1)+1  # we want primes larger than start and only odd numbers (hence the +1)
    stop=pow(2,l)       # but smaller than stop
    p=start
    while not is_prime_fast(p):
    # while not is_prime_slow(p):
        p=random.randrange(start, stop, 2)  # because primes greater than 2 are odd, we only check for odd numbers (hence step=2)
        count_passes+=1
    # print("went through {} passes".format(count_passes))
    return(p)

def gcd(a, b):
    '''
    Computes the gcd of a and b using the euclidian algorithm
    '''
    assert is_number(a) and is_number(b), "Invalid number a or b"
    while b!=0:
        a, b = b, a%b
    return(a)

def lcm(a, b):
    '''
    Returns the lowest common multiple of a and b using the gcd function for speed
    '''
    assert is_number(a) and is_number(b), "Invalid number a or b"
    return(a*b//gcd(a, b))

def choose_exponent(n):
    '''
    In theory the goal is to look for an integer e such that:
            1 < e < lambda(n)
            gcd(e, lambda(n)) = 1
    In practice it is easier to return a choice from a list of candidates and hope that one of them work
    This implementation is satisfactory for a MVP
    '''
    assert is_number(n), "Invalid input"

    possible = [3,5,17,257,65537]
    for i in possible:
        if n%i:
            return(i)
    print("Choosing exponent failed")

def inverse(a, b):
    '''
    This function computes the multiplicative inverse x of a mod b
            a*x=1 (mod b)
    using the extended Euclidian algorithm
    For more information https://brilliant.org/wiki/extended-euclidean-algorithm/
    '''
    assert is_number(a) and is_number(b), "Invalid number a or b"
    b2=b # we need a trace of b to potentially rectify the last value of x
    x, u = 0, 1 # initialize the sequence
    while a!=0: # as long as we haven't reached the gcd (last value before remainder = 0)
        q, r = b//a, b%a # Euclidian division
        m = x-u*q        # sequence of coefficient
        b, a, x, u = a, r, u, m # Update the values for the next iteration
    if x<0:
        x+=b2 # rectify the value of x to have a positive number
    return(x)

def encode_message(message, blocksize):
    '''
    This function takes a message as input, encodes it in binary so it can be encrypted with the RSA scheme
    Blocksize is intended to take the bit-length of the key as value to add the padding
    TODO break this function into encode and padd (because padding with 0 is not the best)
    '''
    try:
        message=str(message) # make sure the message is a string
    except:
        raise AssertionError("Invalid input, message cannot be converted to string")
    assert is_number(blocksize), "Invalid number blocksize"
    blocks=""
    for letter in message:
        blocks+="{0:08b}".format(ord(letter)) # displays the ascii code as a 8 bits long binary integer
    if len(blocks)%blocksize>0:
        blocks=(blocksize-len(blocks)%blocksize)*"0"+blocks # pad the blocks to reach the end of the blocksize
    return(blocks) # This returns a long string, it is intended to be chunked into blocks of size blocksize

def ascii_to_hex(message):
    '''
    returns the string of hex values of the ascii string
    '''
    hex_string = ""
    for letter in message:
        hex_code = "\\x{0:02X}".format(ord(letter))
        hex_string += hex_code
    return(hex_string)

def hex_to_ascii(hex_string):
    '''
    return the ascii string that corresponds to the hex string
    hex characters have to be in format (backslash)x** with ** a valid hex number in the ascii range
    '''
    ascii_string = ""
    try:
        for letter in hex_string.split("\\x")[1:]:
            ascii_string += chr(int(letter, 16))
        return(ascii_string)
    except:
        return("Invalid hex string")

def string_to_blocks(message, blocksize):
    '''
    This function takes a string as input and returns an iterator of strings of size blocksize
    This is intended for two purposes :
            - chunk the binary string in blocks of length len(pub_key) for the encryption and decryption
            - chunk the binary string in blocks of size 8 to decode in ascii
    '''
    assert is_number(blocksize), "Invalid argument blocksize must be an integer"
    for i in range(0, len(message), blocksize):
        yield message[i: i+blocksize]

def crypt_block(block, exponent, modulus):
    '''
    This function encrypts the block with the public key and the exponent
            1 - encrypt the block with the exponent and the modulus
            2 - return the new string
    Figure out how to chunk the cipher block into blocks of the size of the original block and pad with zeros so that the calculations still work (prepend zeros)
    The decryption uses the same algorithm with a different value of exponent
    '''
    try:
        plain=int(block, 2) # convert the binary number into decimal
    except:
        raise AssertionError("Block could not be converted to an int")
    blocksize=len(block) # retreive the blocksize
    cipher=pow(plain, exponent, modulus) # perform the encryption operation
    bin_cipher=bin(cipher)[2:]
    if len(bin_cipher)%blocksize>0:
        bin_cipher="0"*(blocksize-len(bin_cipher)%blocksize)+bin_cipher # append some zeros to return a block of length multiple of the original block (with same binary value)
    return(bin_cipher)

def display_bin_block(bin_message):
    '''
    This function returns the string in ascii code that corresponds to the binary message in input.
    '''
    bin_chars=string_to_blocks(bin_message, 8) # chunks the string to get 8 bits blocks (for ascii)
    message=""
    for bin_char in bin_chars:
        message+=chr(int(bin_char, 2)) # converts each block in ascii
    return(message)


def RSA(bitlength, message):
    '''
    Implements the generation of keys, encryption and decryption of message
    '''
    # Make the program deterministic

    # random.seed(1) # this seed makes the program not work properly

    # Generating the primes
    p = choose_prime(bitlength)
    q = choose_prime(bitlength)

    # Creating the keys

    n = p*q

    lowest_multiple = lcm(p-1, q-1)

    e = choose_exponent(lowest_multiple)    # part of the public key
    d = inverse(e, lowest_multiple)         # private key

    # print("p = [{}]\nq = [{}]\nn = [{}]\ne = [{}]\nd = [{}]".format(p, q, n, e, d))
    print("d*e = {} (mod {})".format((d*e)%lowest_multiple, "lambda"))

    # Encode the message

    bin_message = encode_message(message, 2*bitlength) # turn the message in binary
    bin_message_blocks = string_to_blocks(bin_message, 2*bitlength) # generator of blocks

    # Encrypt the message

    bin_cipher = ""
    for bin_block in bin_message_blocks:
        bin_cipher += crypt_block(bin_block, e, n)

    # Decode the cipher

    hex_cipher = ascii_to_hex(display_bin_block(bin_cipher))

    # Encode the cipher

    bin_cipher = encode_message(hex_to_ascii(hex_cipher), 2*bitlength)

    bin_message_blocks = string_to_blocks(bin_cipher, 2*bitlength) # generator of blocks

    # Decrypt the cipher

    bin_plain = ""
    for bin_block in bin_message_blocks:
        bin_plain += crypt_block(bin_block, d, n)

    # Display the messages

    # print("Original message =\n[{}]".format(ascii_to_hex(display_bin_block(bin_message))))
    # print("\n"+"#"*30)
    # print("Encrypted message =\n[{}]".format(hex_cipher))
    # print("\n"+"#"*30)
    # print("Decrypted message =\n[{}]".format(ascii_to_hex(display_bin_block(bin_plain))))
    print("Original message =\n[{}]".format(display_bin_block(bin_message)))
    # print("\n"+"#"*30)
    # print("Encrypted message =\n[{}]".format(hex_cipher))
    print("\n"+"#"*30)
    print("Decrypted message =\n[{}]".format(display_bin_block(bin_plain)))

class RSA_key():
    '''
    Class to hold all the attributes of the RSA scheme
            - public key
            - public exponent
            - private key
    Also hold the methods to
            - encrypt a message
            - decrypt a message
    '''
    def __init__(self, bitlength):
        '''
        Method to instanciate the class, it will generate the keys
        '''
        self.bitlength = bitlength

        # Generate the primes (must be kept "private" - python doesn't have private attributes or methods)

        self.__p = choose_prime(self.bitlength)
        self.__q = choose_prime(self.bitlength)

        # Creating the keys

        self.n = self.__p*self.__q

        lowest_multiple = lcm(self.__p-1, self.__q-1)

        self.e = choose_exponent(lowest_multiple)    # part of the public key
        self.__d = inverse(self.e, lowest_multiple)

    def encrypt_message(self, message):
        '''
        Encrypt a message with the key
        '''
        # Encode the mesage

        bin_message = encode_message(message, 2*self.bitlength) # turn the message in binary
        bin_message_blocks = string_to_blocks(bin_message, 2*self.bitlength) # generator of blocks

        # Encrypt the message

        bin_cipher = ""
        for bin_block in bin_message_blocks:
            bin_cipher += crypt_block(bin_block, self.e, self.n)

        return(display_bin_block(bin_cipher)) # return the ascii string of the encrypted message

    def decrypt_message(self, cipher):
        '''
        Decrypt the cipher text using the key
        '''
        # Encode the cipher text

        bin_cipher = encode_message(cipher, 2*self.bitlength)

        bin_message_blocks = string_to_blocks(bin_cipher, 2*bitlength) # generator of blocks

        # Decrypt the cipher text

        bin_plain = ""
        for bin_block in bin_message_blocks:
            bin_plain += crypt_block(bin_block, self.__d, self.n)

        return(display_bin_block(bin_plain))

if __name__=="__main__":

    def test(n, message, debug=True):
        '''
        Execute a function and displays the time it took
        '''
        # Start the clock
        t=time.time()

        # Execute the function

        RSA(n, message)

        # Display time

        t=time.time()-t
        print("\nTest for param n = {}\ttime = {:.3f}s".format(n, t))

        return(t)

    bitlength=512 # bitlength of the key
    # message="Hello world!" # message to encrypt
    message = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do"
    debug=True # activate the debug traces
    test(bitlength, message)
