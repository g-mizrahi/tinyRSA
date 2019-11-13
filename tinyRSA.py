# Implement the RSA encryption and decryption algorithms
# Implement a crack of the algorithm for small numbers


# RSA algorithm
# 4 steps :
#       - Key generation
#       - Key distribution
#       - Key encryption
#       - Key decryption
# refer to https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29

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
    count_passes=0
    start=pow(2,l)+1    # we want primes larger than start
    stop=pow(2,l+1)     # but smaller than stop
    p=start
    while not is_prime_fast(p):
        p=random.randrange(start, stop, 2)  # because primes greater than 2 are odd, we only check for odd numbers
        count_passes+=1
    # print("went through {} passes".format(count_passes))
    return(p)

def lcm(a, b):
    '''
    Returns a common multiple of a and b
    '''
    c=min(a, b)
    d=max(a, b)
    # order a and b to optimize the search
    e=1
    # because the result is a multiple of both it is easier to look for it amongs the multiples of the bigger number (fewer iterations)
    while (d*e)%c!=0:
        e+=1
    # print("{} is le lcm of {} and {}".format(e*d, c, d))
    return(d*e)

def choose_exponent(n):
    '''
    In theory the goal is to look for an integer e such that:
            1 < e < lambda(n)
            gcd(e, lambda(n)) = 1
    In practice it is easier to return pow(2, 16)+1 or 3 depending on the size of n
    This implementation is satisfactory for a POC
    '''
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

def encrypt_message(message, exponent, modulus):
    '''
    This function encrypts the message with the public key and the exponent
            1 - divide in blocks (one block per letter to avoid padding issues ?)
            2 - encrypt each block
            3 - join the ciphertext letters
    '''
    cipher=[]
    for letter in message:
        cipher.append(str(pow(ord(letter), exponent, modulus)))
    return(', '.join(cipher))

def decrypt_message(message, exponent, modulus):
    '''
    This function encrypts the message with the private key and the exponent
            1 - divide in blocks (split along new line)
            2 - decrypt each block
            3 - join the ciphertext letters
    '''
    plain=[]
    for letter in message.split(', '):
        plain.append(chr(pow(int(letter), exponent, modulus)))
    return(''.join(plain))

def main():
    print("Generating prime numbers")
    p=choose_prime(19)
    q=choose_prime(21)
    print("(p, q) = ({}, {})".format(p, q))
    # print("Verify p, q are prime [{}|{}]".format(is_prime_slow(p), is_prime_slow(q)))
    n=p*q
    print("Public key \tn = {}".format(n))
    e=choose_exponent(n)
    print("Public exponent\te = {}".format(e))
    d=compute_inverse(e, lcm(p-1, q-1))
    print("Private key\td = {}".format(d))
    message="hello world"
    cipher=encrypt_message(message, e, n)
    plain=decrypt_message(cipher, d, n)
    print("{} -> \n{} -> \n{}".format(message, cipher, plain))
    return(0)

if __name__=="__main__":

    def test(n):
        # Start the clock
        t=time.time()

        p=choose_prime(n)
        # print("p={}".format(p))

        # Stop the clock and display time
        t=time.time()-t
        print("\ttime = {:.3f}s".format(t))

        return(t)
    # t=0
    # for i in range(10):
    #     print("test {} for bit length of {}".format(i+1, 1000))
    #     t+=test(1000)
    # print("Average time = {:.3f}s".format(t/10))
    main()
    # print(compute_inverse(17, 43))
