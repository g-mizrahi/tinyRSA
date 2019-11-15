# Guilhem Mizrahi 11/2019

# In python3 cli
# from app import db
# db.create_all()

# imports for Flask, the Flask db handler and the tinyRSA library
from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from tinyRSA import *

# Initialize the app and the database (called rsa)
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rsa.db'
db = SQLAlchemy(app)

# Create the database scheme

class RSA_scheme(db.Model):
    '''
    This class is used to keep track of the keys so a user to encrypt and decrypt with the same key.
    Consider having a feature with accounts and store keys that belong to someone to that they can reuse them.
    WARNING the maximum size for integers in SQLite is 2^63. Therefore 31 and 30 are the maximum bit lengths for p and q
    Consider storing integers as strings and converting with Python
    '''
    id = db.Column(db.Integer, primary_key=True)
    p = db.Column(db.String(310), unique=False)
    q = db.Column(db.String(310), unique=False)
    n = db.Column(db.String(620), unique=False)
    e = db.Column(db.String(10), unique=False)
    d = db.Column(db.String(620), unique=False)

    def __repr__(self):
        return("<id {}\nPublic key {}>".format(self.id, self.n))

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
    '''
    if request.method=='GET':
        return(render_template("index.html"))
    elif request.method=='POST':
        if request.form['generate']:
            p=choose_prime(512)
            q=choose_prime(512)
            n=p*q
            e=choose_exponent(n)
            d=compute_inverse(e, lcm(p-1, q-1))
            new_key=RSA_scheme(p=str(p), q=str(q), n=str(n), e=str(e), d=str(d))
            # return("p={}\nq={}\nn={}\ne={}\nd={}".format(str(p),str(q),str(n),str(e),str(d)))
            try:
                db.session.add(new_key)
                db.session.commit()
                # return(str(new_key.id))
                key=RSA_scheme.query.filter_by(id=str(new_key.id)).all()
                return(render_template("encrypt.html", keys=key))
            except:
                return("Failed at generating the keys")
        else:
            return("Bad form")
    else:
        return("Bad request")

# Endpoint to encrypt the content of the form
@app.route('/encrypt/<int:id>', methods=['POST'])
def encrypt(id):
    '''
    This function encrypts the content of the form using the key associated with id
    '''
    key=RSA_scheme.query.filter_by(id=str(id)).all()
    message=request.form['plain']
    cipher=encrypt_message(message, int(key[0].e), int(key[0].n))
    return(render_template("encrypt.html", keys=key, cipher=cipher))

# Endpoint to decrypt the content of the form
@app.route('/decrypt/<int:id>', methods=['POST'])
def decrypt(id):
    '''
    This function decrypts the content of the form using the keys associated with id
    '''
    key=RSA_scheme.query.filter_by(id=str(id)).all()
    cipher=request.form['cipher']
    message=decrypt_message(cipher, int(key[0].d), int(key[0].n))
    return(render_template("encrypt.html", keys=key, plain=message))

if __name__=="__main__":
    app.run(debug=True)
