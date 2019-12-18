# Guilhem Mizrahi 11/2019

# In python3 cli
# from app import db
# db.create_all()

# imports for Flask, the Flask db handler and the tinyRSA library
from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy

import tinyRSA_lib as RSAlib
from tinyRSA_key import TinyRSA_key as RSAkey
from tinyRSA_message import TinyRSA_message as RSAmessage

# Initialize the app and the database (called rsa)
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rsa.db'
db = SQLAlchemy(app)

# Create the database scheme

class tinyRSA_scheme(db.Model):
    '''
    This class is used to keep track of the keys so a user to encrypt and decrypt with the same key.
    Consider having a feature with accounts and store keys that belong to someone to that they can reuse them.
    WARNING the maximum size for integers in SQLite is 2^63. Therefore 31 and 30 are the maximum bit lengths for p and q
    Consider storing integers as strings and converting with Python
    '''
    id = db.Column(db.Integer, primary_key=True)
    p = db.Column(db.String(512), unique=False)
    q = db.Column(db.String(512), unique=False)
    # n = db.Column(db.String(620), unique=False)
    e = db.Column(db.String(64), unique=False)
    # d = db.Column(db.String(620), unique=False)

    def __repr__(self):
        return("<id {}>".format(self.id))

# The default route, loads the home page
@app.route('/', methods=['POST','GET'])
def index():
    '''
    This function serves the home page
    If the method is GET
            then just load the default page
    If the method is POST
            then someone just asked to create new keys. Perform the logic and redirect
    Security checks for request and form name.

    TODO
            - Retreive the value of the bitlength from the form
    '''
    if request.method=='GET':       # If the request is get just serve the home page
        return(render_template("index.html"))
    elif request.method=='POST':    # If request is post then execute logic
        try:                        # Check for validity of key length
            bitlength = int(request.form["bitlength"])
            if bitlength<2 or bitlength>1024:
                return("Invalid bitlength for the key, provide an integer ranging from 2 to 1024")
            # else:
            #     return("Bitlength = {}".format(bitlength))
        except:
            return("Invalid bitlength for the key, provide an integer ranging from 2 to 1024")
        # Once here we know the bitlength is valid
        key = RSAkey()
        key.create_new(bitlength)
        new_key=RSA_scheme(p=key.p, q=key.q, e=key.e)
        try:
            db.session.add(new_key)
            db.session.commit()
            return(render_template("encrypt.html", keys=key, ids=new_key.id))
        except:
            return("Failed at generating the keys")
    else:
        return("Bad request")
    # elif request.method=='POST':
    #     if request.form['generate']:
    #         try:
    #             bitlength = int(request.form['bitlength'])
    #
    #             new_key=RSA_scheme(p=str(p), q=str(q), n=str(n), e=str(e), d=str(d))
    #             # return("p={}\nq={}\nn={}\ne={}\nd={}".format(str(p),str(q),str(n),str(e),str(d)))
    #             try:
    #                 db.session.add(new_key)
    #                 db.session.commit()
    #                 key=RSA_scheme.query.filter_by(id=str(new_key.id)).all()
    #                 return(render_template("encrypt.html", keys=key))
    #             except:
    #                 return("Failed at generating the keys")
    #         except:
    #             return("Wrong bitlength")
    #     else:
    #         return("Bad form")
    # else:
    #     return("Bad request")

# Endpoint to encrypt the content of the form
@app.route('/encrypt/<int:id>', methods=['POST'])
def encrypt(id):
    '''
    This function encrypts the content of the form using the key associated with id
    '''
    key=RSA_scheme.query.filter_by(id=str(id)).all()
    message=request.form['plain']

    # Perform the encryption algorithm on the plain text

    msg = RSAmessage()
    msg.add_plain(message)
    p = key[0].p
    q = key[0].q
    e = key[0].e
    
    # bitlength = 512
    #
    # bin_message = encode_message(message, 2*bitlength) # turn the message in binary
    # bin_message_blocks = string_to_blocks(bin_message, 2*bitlength) # generator of blocks
    #
    # # Encrypt the message
    #
    # e = int(key[0].e)
    # n = int(key[0].n)
    #
    # bin_cipher = ""
    # for bin_block in bin_message_blocks:
    #     bin_cipher += crypt_block(bin_block, e, n)
    #
    # cipher = display_bin_block(bin_cipher)
    # cipher = ascii_to_hex(cipher)
    # return(render_template("encrypt.html", keys=key, cipher=cipher))

# Endpoint to decrypt the content of the form
@app.route('/decrypt/<int:id>', methods=['POST'])
def decrypt(id):
    '''
    This function decrypts the content of the form using the keys associated with id
    '''
    key=RSA_scheme.query.filter_by(id=str(id)).all()
    cipher=request.form['cipher']

    # Perform the decryption algorithm on the message

    # Encode the message

    bitlength = 512

    cipher = hex_to_ascii(cipher)

    bin_cipher = encode_message(cipher, 2*bitlength) # turn the message in binary
    bin_cipher_blocks = string_to_blocks(bin_cipher, 2*bitlength) # generator of blocks

    # Decrypt the message

    d = int(key[0].d)
    n = int(key[0].n)

    bin_plain = ""
    for bin_block in bin_cipher_blocks:
        bin_plain += crypt_block(bin_block, d, n)

    plain = display_bin_block(bin_plain)
    plain = hex_to_ascii(ascii_to_hex(plain))
    # return(plain)
    return(render_template("encrypt.html", keys=key, plain=plain))

if __name__=="__main__":
    app.run(debug=True)
