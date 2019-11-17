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
    start=pow(2,l-1)+1    # we want primes larger than start
    stop=pow(2,l)     # but smaller than stop
    p=start
    while not is_prime_fast(p):
        p=random.randrange(start, stop, 2)  # because primes greater than 2 are odd, we only check for odd numbers
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

    if n>65537:
        # in this case the value of lambda(n) is also greater that pow(2, 16) and 65537 is a valid answer
        return(65537)
    else:
        # in this case, to avoid confusion and be faster 3 is also a valid answer
        return(3)

def compute_inverse(a, n):
    '''
    This function computes the multiplicative inverse x of a mod n
            a*x=1 (mod n)
    using the extended Euclidian algorithm
    '''
    assert is_number(a) and is_number(n), "Invalid number a or n"
    # Initialize the variables to define the sequence
    old_s=1
    s=0
    old_r=a
    r=n
    # As long as the remainder is not 0, compute the next step
    while r!=0:
        q=old_r//r
        old_r, r=r, old_r-q*r
        old_s, s=s, old_s-q*s
    return(old_s%n)

def encode_message(message, blocksize):
    '''
    This function takes a message as input, encodes it in binary so it can be encrypted with the RSA scheme
    Blocksize is intended to take the bit-length of the key as value to add the padding
    '''
    try:
        message=str(message) # make sure the message is a string
    except:
        raise AssertionError("Invalid input, message cannot be converted to string")
    assert is_number(blocksize), "Invalid number blocksize"
    blocks=""
    for letter in message:
        blocks+="{0:08b}".format(ord(letter)) # displays the ascii code as a 8 bits long binary integer
    blocks=blocks+(blocksize-len(blocks)%blocksize)*"0" # pad the blocks to reach the end of the blocksize
    return(blocks) # This returns a long string, it is intended to be chunked into blocks

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
        plain=int(block, 2)
    except:
        raise AssertionError("Block could not be converted to an int")
    blocksize=len(block)
    cipher=pow(plain, exponent, modulus)
    bin_cipher=bin(cipher)[2:]
    bin_cipher+="0"*(blocksize-len(bin_cipher)%blocksize) # append some zeros to return a block of length multiple of the original block (with same binary value)
    return(bin_cipher)

def display_bin_block(bin_message):
    '''
    This function returns the string in ascii code that corresponds to the binary message in input.
    '''
    bin_chars=string_to_blocks(bin_message, 8)
    message=""
    for bin_char in bin_chars:
        message+=chr(int(bin_char, 2))
    return(message)

# def decrypt_message(message, exponent, modulus):
#     '''
#     This function encrypts the message with the private key and the exponent
#             1 - divide in blocks (split along new line)
#             2 - decrypt each block
#             3 - join the ciphertext letters
#     '''
#     plain=[]
#     for letter in message.split(', '):
#         plain.append(chr(pow(int(letter), exponent, modulus)))
#     return(''.join(plain))

def main(bitlength, message, debug=False):
    t0=time.time()
    print("Generating prime numbers")
    p=choose_prime(bitlength)
    q=choose_prime(bitlength)
    print("Done generating the prime numbers")
    t1=time.time()-t0 # time taken to generate the prime numbers
    n=p*q
    e=choose_exponent(n) # we don't need to measure the time, because of the implementation we know it is O(1)
    t0=time.time()
    lowest_multiple = lcm(p-1, q-1)
    t2=time.time()-t0 # time taken to compute the lcm (used to be long with a naive method)
    t0=time.time()
    d=compute_inverse(e, lowest_multiple)
    t3=time.time()-t0 # time taken to compute the inverse
    t0=time.time()
    bin_message=encode_message(message, n) # message encoded in binary
    bin_blocks=string_to_blocks(bin_message, n) # generator with the blocks to encode separately (in this case probably just one block)
    t4=time.time()-t0 # time taken to encode the message
    t0=time.time()
    bin_cipher=""
    for bin_block in bin_blocks: # Treat each block separately
        bin_cipher+=crypt_block(bin_block, e, n) # encrypt each block
    t5=time.time()-t0 # time taken to encrypt the message
    cipher=display_bin_block(bin_cipher) # Convert back to ascii

    if debug:
        print("#"*30)
        print("p = [{}]\nq = [{}]".format(p, q))
        print("Public key \tn = [{}]".format(n))
        print("Public exponent\te = [{}]".format(e))
        print("lcm = [{}]".format(lowest_multiple))
        print("Private key\td = [{}]".format(d))
        print("#"*30)
        print("Original message = [{}]".format(message))
        print("Encrypted binary message = [{}]".format(bin_cipher))
        print("Encrypted message = [{}]".format(cipher))
        print("#"*30)
        print("Generating prime numbers took [{:.3f}]s".format(t1))
        print("Generating lcm took [{:.3f}]s".format(t2))
        print("Generating private key took [{:.3f}]s".format(t3))
        print("Encoding message took [{:.3f}]s".format(t4))
        print("Encrypting message took [{:.3f}]s".format(t5))
    return(t1+t2+t3)

if __name__=="__main__":

    def test(n, message, debug=False):
        '''
        Execute a function and displays the time it took
        '''
        # Start the clock
        t=time.time()

        main(n, message, debug) # we want to test the efficiency of main

        t=time.time()-t
        print("\nTest for param n = {}\ttime = {:.3f}s".format(n, t))

        return(t)

    n=512 # bitlength of the key
    message="Hello world!" # message to encrypt
    debug=True # activate the debug traces

    # test(n, message, debug)

    # cannot fit 'int' into an index-sized integer
