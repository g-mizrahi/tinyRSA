# This file is part of the TinyRSA project.
# This project is about implementing a very simple (and insecure) RSA cryptosystem to play around
# The main goal is to be able to change the length of the key for hacking purposes
#
# Guilhem Mizrahi 12/2019
#
# This file contains the set of functions that are underlying to TinyRSA
# Essentially these functions are mathematical functions to perform arithmetics
#
# The package random is required
#
# List of functions :
#       - is_prime_slow             (check if a number is prime)
#       - is_prime_fast             (check if a number is prime, faster)
#       - prime_with_bitlength      (choose a prime with a selected bitlength)
#       - gcd                       (compute the gcd)
#       - lcm                       (compute the lcm)
#       - multiplicative_inverse    (compute the multiplicative inverse of a number mod another)
#
# The beginning of each function can be easily reached by searching for the string "START function name"


import random

# START is_prime_slow FUNCTION

def is_prime_slow(n):
    '''
    Test if a number is prime. Return True if it is and False otherwise.
    Using the most simple method of checking all numbers up to the square root.
    Complexity is O(sqrt(n))
    This method is very naive and isn't actually used in the code, it is left here because it was part of the PoC for keylength of 16 bits
    '''
    if not isinstance(n, int) or n<2:   # Check if n is a integer, if it isn't then it is not a prime
                                        # Also check if n<2 in which case it isn't prime
        return(False)
    else:
        limit=math.ceil(math.sqrt(n))
        for i in range(2, limit+1):
            if n%i==0:                  # If there is a divisor in the range [2, sqrt(n)] then n is not prime
                return(False)
        return(True)                    # If there are no divisors then n is prime

# END is_prime_slow FUNCTION

# START is_prime_fast FUNCTION

def is_prime_fast(n):
    '''
    Check if a number is likely to be prime using the Miller-Rabin primality check in a single pass. To have more accuracy, the program would have to have to perform multiple passes

    Complexity is in log2(n) for a single pass.
    Depending on how many passes we want to implement the complexity is likely to change

    For more information refer to
    https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    '''
    if not isinstance(n, int) or n<2:   # Check if n is a integer, if it isn't then it is not a prime
                                        # Also check if n<2 in which case it isn't prime
        return(False)
    else:
        # we want to decompose n=d*2^s+1 with d odd
        s=0
        while (n-1)%pow(2, s+1)==0: # we want to check for the max value of r
            s+=1
        d=(n-1)//pow(2, s)          # d is obtained by a simple division

        # Prepare for multiple loops on a
        for i in range(10): # do 10 passes in the loop

            a=random.randint(2, n-1)    # if n is prime then a^d=1(mod n) or a^(d*2^r)=-1(mod n) for some 0<=r<=s-1
                                        # if we can verify this for all values of a then n is likely to be prime (but not necessarily)
            witness=pow(a, d, n)
            if not (witness==1 or witness==n-1):
                for j in range(s-1):    # we have to check if a^(d*2^r)=-1(mod n) for some 0<=r<=s-1 (in which case n is probably prime)
                    witness=pow(witness, 2, n)
                    if (witness==n-1):
                        return(True)
                return(False)           # otherwise we know for sure that n is composite
                # If it never got out of the loop then it mean that it never found a root in the Z/nZ among the possible witnesses so we return False
        # If False never got returned in any pass of the loop then n is very likely to be prime
        return(True)

# END is_prime_fast FUNCTION

# START prime_with_bitlength FUNCTION

def prime_with_bitlength(l):
    '''
    Will return a random prime of bit length l
    This function implements a monte carlo method of finding prime numbers by choosing random numbers until it has found a prime.

    The range of value is adjusted so that multiplying two primes of length l procudes a number of length 2l.
    '''
    # Input check
    if not (isinstance(l, int) and l>=2):
        raise ValueError("Invalid bitlength, it should be an integer strickly greater than 1")

    count_passes=0
    start=int(pow(2,l-1)*(2**0.5))+1    # we want primes larger than start and only odd numbers (hence the +1) multiply by sqrt to make sure the public key is of the expected length
    stop=pow(2,l)                       # but smaller than stop
    p=start
    while not is_prime_fast(p):
        p=random.randrange(start, stop, 2)  # because primes greater than 2 are odd, we only check for odd numbers (hence step=2)
                                            # think about optimizing this part (6k+-1)?
        count_passes+=1
    return(p)

# END prime_with_bitlength FUNCTION

# START gcd FUNCTION

def gcd(a, b):
    '''
    Computes the gcd of a and b using the euclidian algorithm
    '''
    if not (isinstance(a, int) and isinstance(b, int)):
        raise ValueError("Invalid input for gcd, should be two integers")

    while b!=0:
        a, b = b, a%b   # gcd(a, b) = gcd(b, a%b)
                        # keep going until we reach a%b = 0 in which case gcd(a, b) = last remainder > 0
    return(a)

# END gcd FUNCTION

# START lcm FUNCTION

def lcm(a, b):
    '''
    Returns the lowest common multiple of a and b using the gcd function for speed
    '''
    if not (isinstance(a, int) and isinstance(b, int)):
        raise ValueError("Invalid input for lcm, should be two integers")

    return(a*b//gcd(a, b))

# END lcm FUNCTION

# START multiplicative_inverse FUNCTION

def multiplicative_inverse(a, b):
    '''
    This function computes the multiplicative inverse x of a mod b
            a*x=1 (mod b)
    using the extended Euclidian algorithm
    For more information https://brilliant.org/wiki/extended-euclidean-algorithm/

    In the context of RSA this function is used with a = e (the exponent) and b = lambda(n) (Carmichael's totient function https://en.wikipedia.org/wiki/Carmichael_function) and e is chosen such that gcd(e, lambda(n)) = 1
    The inverse will be the private key
    '''
    if not (isinstance(a, int) and isinstance(b, int)):
        print("Invalid input for multiplicative inverse")
        raise SystemExit(1)

    b2=b        # we need a trace of b to potentially rectify the last value of x
    x, u = 0, 1 # initialize the sequence
    while a!=0: # as long as we haven't reached the gcd (last value before remainder = 0)
        q, r = b//a, b%a        # Euclidian division
        m = x-u*q               # sequence of coefficient
        b, a, x, u = a, r, u, m # Update the values for the next iteration
    if not b==1:                # At this point if b is not 1 then there is no inverse, the inputs are not coprime and there is probably something wrong with the prime number generation step
        print("Couldn't compute inverse, a and b are probably not coprime")
        raise SystemExit(1)
    if x<0:
        x+=b2   # rectify the value of x to have a positive number
    return(x)

# END multiplicative_inverse FUNCTION

if __name__ == '__main__':
    print(multiplicative_inverse(17, 43))
    print(is_prime_fast(11990449251145931745564215483884623262016981102977135227921664818241599323747134700686216463266625884413310564264540932840138433670632832957894634174353833))
    print(prime_with_bitlength(1024))
