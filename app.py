# Guilhem Mizrahi 11/2019

# In python3 cli
# from app import db
# db.create_all()

from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from tinyRSA import *

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rsa.db'
db = SQLAlchemy(app)

class RSA_scheme(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    p = db.Column(db.Integer, unique=False)
    q = db.Column(db.Integer, unique=False)
    n = db.Column(db.Integer, unique=False)
    e = db.Column(db.Integer, unique=False)
    d = db.Column(db.Integer, unique=False)

    def __repr__(self):
        return("<id {}\nPublic key {}>".format(self.id, self.n))

# Maybe not necessary
# class Message(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     plain = db.column(db.String(200))
#     cipher = db.Column(db.String(200))
#
#     def __repr__(self):
#         return("<id {}\nMessage {}>".format(self.id, self.plain))

@app.route('/', methods=['POST','GET'])
def index():
    if request.method=='GET':
        return(render_template("index.html"))
    elif request.method=='POST':
        if request.form['generate']:
            p=choose_prime(20)
            q=choose_prime(20)
            n=p*q
            e=choose_exponent(n)
            d=compute_inverse(e, lcm(p-1, q-1))
            new_key=RSA_scheme(p=p, q=q, n=n, e=e, d=d)
            # return("p={}\nq={}\nn={}\ne={}\nd={}".format(p,q,n,e,d))
            try:
                db.session.add(new_key)
                db.session.commit()
                # return(str(new_key.id))
                key=RSA_scheme.query.filter_by(id=str(new_key.id)).all()
                return(render_template("encrypt.html", keys=key))
            except:
                return("Failed at generating the keys")
            # Generate the key and return the template with the key
            # Redirect to the encryption page
        else:
            return("Bad form")
    else:
        return("Bad request")

@app.route('/encrypt/<int:id>', methods=['POST'])
def encrypt(id):
    key=RSA_scheme.query.get_or_404(id)
    message=request.form['plain']
    # ENCRYPT THE MESSAGE
    cipher=message
    return(render_template("encrypt.html", keys=key, cipher=cipher))

# @app.route('/delete/<int:id>')
# def delete(id):
#     name_to_delete = Name.query.get_or_404(id)
#     try:
#         db.session.delete(name_to_delete)
#         db.session.commit()
#         return(redirect('/'))
#     except:
#         return("Something went wrong")
#
# @app.route('/update/<int:id>', methods=['GET', 'POST'])
# def update(id):
#     name = Name.query.get_or_404(id)
#     if request.method=="POST":
#         name.name=request.form['name']
#         try:
#             db.session.commit()
#             return(redirect('/'))
#         except:
#             return("Something went wrong")
#     else:
#         return(render_template("update.html", name=name))

if __name__=="__main__":
    app.run(debug=True)
