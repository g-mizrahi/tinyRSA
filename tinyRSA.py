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
#       - implement security checks, fail gracefully
#       - better encoding, padding etc of text before encryption
#       - better decoding of data after decryption
# Frontend
#       - better looking page : minimalist design
#       - better display of keys and text
#       - possibility to select the value of the bit length of keys
#       - better explanation of process

# With 1024 bits long primes (2048 bits RSA key) it takes between 1.5 and 7 seconds
# Almost 100% of that time is spent generating the prime numbers

import math
import random
import time

def is_number(n):
    return(isinstance(n, int))

def is_prime_slow(n):
    '''
    Test if a number is prime. Return True if it is and False otherwise
    Using the most simple method of checking all numbers up to the square root
    Complexity is O(sqrt(n))
    '''
    if not is_number(n) or n<2:
        return(False)
    else:
        limit=math.ceil(math.sqrt(n))
        for i in range(2, limit+1):
            if n%i==0:
                return(False)
        return(True)

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
    By choosing random numbers until it has a prime
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
    Returns a common multiple of a and b
    '''
    assert is_number(a) and is_number(b), "Invalid number a or b"
    return(a*b//gcd(a, b))

def choose_exponent(n):
    '''
    In theory the goal is to look for an integer e such that:
            1 < e < lambda(n)
            gcd(e, lambda(n)) = 1
    In practice it is easier to return pow(2, 16)+1 or 3 depending on the size of n
    This implementation is satisfactory for a POC
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

def string_to_blocks(message, blocksize):
    '''
    This function takes a string as input and returns an iterator of strings of size blocksize
    This is intended for two purposes :
            - chunk the binary string in blocks of length len(key) for the encryption and decryption
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

def crypt_number(number, exponent, modulus):
    '''
    Performs the encryption or decryption algorithm on the number
    '''
    return(pow(number, exponent, modulus))

def display_bin_block(bin_message):
    '''
    This function returns the string in ascii code that corresponds to the binary message in input.
    '''
    bin_chars=string_to_blocks(bin_message, 8)
    message=""
    for bin_char in bin_chars:
        message+=chr(int(bin_char, 2))
    return(message)

def RSA(bitlength, message):
    '''
    Implement the generation of keys, encryption and decryption of message
    '''
    # Generating the primes
    p = choose_prime(bitlength)
    q = choose_prime(bitlength)

    # Creating the public key

    n = p*q

    # Generating the private key

    lowest_multiple = lcm(p-1, q-1)

    e = choose_exponent(lowest_multiple)
    d = inverse(e, lowest_multiple)

    # Verification phase

    # print("lambda(n) = [{}]".format(lowest_multiple))
    # print("gcd(e, lambda) = [{}]".format(gcd(e, lowest_multiple)))

    # Encode the message

    bin_message = encode_message(message, 2*bitlength) # turn the message in binary
    bin_message_blocks = string_to_blocks(bin_message, 2*bitlength) # generator of blocks

    # Encrypt the message

    bin_cipher = ""
    for bin_block in bin_message_blocks:
        bin_cipher += crypt_block(bin_block, e, n)
    # print("Original binary = [{}]".format(bin_message))
    # print("Encrypted bnary = [{}]".format(bin_cipher))

    # Decrypt the cipher

    bin_message_blocks = string_to_blocks(bin_cipher, 2*bitlength) # generator of blocks
    bin_plain = ""
    for bin_block in bin_message_blocks:
        bin_plain += crypt_block(bin_block, d, n)
    # print("Decrypted binary = [{}]".format(bin_plain))

    # Display the messages

    ascii_message_blocks = string_to_blocks(bin_message, 8)
    ascii_message=""
    for bin_letter in ascii_message_blocks:
        ascii_message += chr(int(bin_letter, 2))

    ascii_cipher_blocks = string_to_blocks(bin_cipher, 8)
    ascii_cipher=""
    for bin_letter in ascii_cipher_blocks:
        ascii_cipher += chr(int(bin_letter, 2))

    ascii_plain_blocks = string_to_blocks(bin_plain, 8)
    ascii_plain=""
    for bin_letter in ascii_plain_blocks:
        ascii_plain += chr(int(bin_letter, 2))

    print("Original message = [{}]".format(ascii_message))
    print("Encrypted message = [{}]".format(ascii_cipher))
    print("Decrypted message = [{}]".format(ascii_plain))


if __name__=="__main__":

    def test(n, message, debug=True):
        '''
        Execute a function and displays the time it took
        '''
        # Start the clock
        t=time.time()

        # main(n, message, debug) # we want to test the efficiency of main
        RSA(n, message)

        t=time.time()-t
        print("\nTest for param n = {}\ttime = {:.3f}s".format(n, t))

        return(t)

    bitlength=1024 # bitlength of the key
    message="Hello world!" # message to encrypt
    debug=True # activate the debug traces
    test(bitlength, message)
