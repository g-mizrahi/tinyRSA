# Guilhem Mizrahi 11/2019

# In python3 cli
# from app import db
# db.create_all()

from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rsa.db'
db = SQLAlchemy(app)

class RSA_scheme(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    p = db.Column(db.Integer)
    q = db.Column(db.Integer)
    n = db.Column(db.Integer)
    e = db.Column(db.Integer)
    d = db.Column(db.Integer)

    def __repr__(self):
        return("<id {}\nName {}>".format(self.id, self.name))

# Maybe not necessary
# class Message(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     plain = db.column(db.String(200))
#     cipher = db.Column(db.String(200))
#
#     def __repr__(self):
#         return("<id {}\nMessage {}>".format(self.id, self.plain))

@app.route('/', methods=['POST', 'GET'])
def index():
    if request.method=='GET':
        return(render_template("index.html"))
    elif request.method=='POST':
        if request.form['generate']:
            # GENERATE THE KEYS
            return(render_template("index.html"))
        if request.form['encrypt']:
            # ENCRYPT THE TEXT WARNING, WE NEED ID SO GET OTHER API END POINT
    else:
        return("Something went wrong")

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
