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
# The original paper on RSA can be found at http://people.csail.mit.edu/rivest/Rsapaper.pdf
#
# List of attributes :
#       - p                 (first prime number)
#       - q                 (second prime number)
#       - n                 (modulus n = p*q is part of the public key)
#       - lowest_multiple   (lcm(p-1, q-1) is used to generate the private key)
#       - e                 (the public exponent, part of the public key)
#       - d                 (the private exponent, part of the private key)
#
#
# List of methods :
#       - __init__          (constructor of the class)
#       - create_new        (generating a new key)
#       - create_from       (generating a key from known values - p, q and e)
#       - get_bitlength     (get the length in bits of the public key n)
#       - choose_exponent   (choose a valid exponent for the public key)
#       - display           (display the attributes of the class)

import tinyRSA_lib as RSAlib

class TinyRSA_key():
    """
    This class describes an RSA key fitting for the TinyRSA project.
    Everything is public even private keys as the goal is not to do encryption but to pay around with the RSA scheme.
    """

    def __init__(self):
        """
        The constructor is just to create the class attributes, the actual generation of the keys will happen in the create_new or create_from methods.
        """
        self.p = None       # first prime number
        self.q = None       # second prime number
        self.n = None       # modulus, part of public key
        self.e = None       # exponent, part of public key
        self.d = None       # private exponent, part of private key

    def display(self):
        """
        This method prints the attributes of the class.
        """
        print("TinyRSA_key object")
        print("\tp = {}".format(self.p))
        print("\tq = {}".format(self.q))
        print("\tn = {}".format(self.n))
        print("\te = {}".format(self.e))
        print("\td = {}".format(self.d))

    def get_bitlength(self):
        """
        This methods returns the bit length of the public key, this value is used to categorize the strength of the key.
        """
        if self.n==None:    # check if the keys have been generated yet
            print("Empty key. Initialize the key with the create_new of create_from methods")
        else:
            return(self.n.bit_length())     # return the number of bits necessary to represent the public key in binary, excluding the sign and leading zeros

    def create_new(self, bitlength = 512):
        """
        This method with generate a new key for the object with prime numbers of specified bitlength. By default the primes are 512 bits long which makes for a 1024 public key length.
        """
        # Input check
        if not (isinstance(bitlength, int) and bitlength > 1):     # The bitlength has to be an integer strickly greater than 1
            raise ValueError("Invalid bitlength for constructor, should be an integer strickly greater than 1")

        # Generate the primes
        self.p = RSAlib.prime_with_bitlength(bitlength) # first prime of specified bitlength
        self.q = RSAlib.prime_with_bitlength(bitlength) # second prime of specified bitlength

        # Generate the public modulus
        self.n = self.p * self.q

        # Generate the public exponent
        lowest_multiple = RSAlib.lcm(self.p-1, self.q-1)    # Carmichael function of n
        self.e = self.choose_exponent(lowest_multiple)      # choose a valid exponent for the public key

        # Generate the private exponent
        # d * e = 1 (mod lowest_multiple)
        self.d = RSAlib.multiplicative_inverse(self.e, lowest_multiple)

    def create_from(self, p, q, e):
        """
        This methods allows for the creation of a key from two prime numbers and a public exponent.

        It still performs the check to see if the input is valid to generate a key.
        """
        # Input check
        if not (isinstance(p, int) and isinstance(q, int) and isinstance(e, int)):
            raise ValueError("Invalid input, expecting three integers")

        if RSAlib.is_prime_fast(p) and RSAlib.is_prime_fast(q):               # The input values have to be valid primes
            lowest_multiple = RSAlib.lcm(p-1, q-1)    # Carmichael function of n
            if RSAlib.gcd(e, lowest_multiple)==1:               # All input is valid
                # Store prime numbers
                self.p = p
                self.q = q

                # Generate the public modulus
                self.n = self.p * self.q

                # Generate the public exponent
                self.e = e

                # Generate the private exponent
                # d * e = 1 (mod lowest_multiple)
                self.d = RSAlib.multiplicative_inverse(self.e, lowest_multiple)
            else:   # The exponent is not valid
                raise ValueError("Invalid exponent")
        else:
            raise ValueError("Numbers not prime, couldn't construct valid RSA key")

    def choose_exponent(self, lowest_multiple):
        """
        This method chooses a valid public exponent for the encryption. This public exponent needs to be coprime with lowest_multiple.

        In theory (in the context of RSA) the goal is to look for an integer e such that:
                1 < e < lambda(n)
                gcd(e, lambda(n)) = 1
        In practice it is easier to return a choice from a list of candidates and hope that one of them work.
        """
        # Input check
        if not isinstance(lowest_multiple, int):    # The input has to be an integer
            raise ValueError("Invalid input to choose an exponent")

        # Choose the exponent from a list of candidates
        possible = [3,5,17,257,65537]           # List of prime numbers candidate to be exponents
        for candidate in possible:
            if lowest_multiple%candidate:       # If the candidate is not a divisor of the input then they are coprime (because the candidate is a prime number)
                return(candidate)
        raise ValueError("Couldn't choose a valid exponent")    # Raise error if no candidate has been returned

if __name__ == '__main__':
    key = TinyRSA_key()
    key.create_new()
    # key.create_from(11990449251145931745564215483884623262016981102977135227921664818241599323747134700686216463266625884413310564264540932840138433670632832957894634174353833, 13103525810977923770843807104907425881745479779982166927021498282574825679771012018988336764600432834357190457702860607586177142996889546935261565070365399, 5)
    key.display()
    print(key.get_bitlength())
