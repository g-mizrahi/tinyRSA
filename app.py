# Guilhem Mizrahi 11/2019

from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///numbers.db'
db = SQLAlchemy(app)

class Name(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)

    def __repr__(self):
        return("<id {}\nName {}>".format(self.id, self.name))

@app.route('/', methods=['POST', 'GET'])
def index():
    if request.method=='POST':
        new_name=request.form['name']
        new_name = Name(name=new_name)
        try:
            db.session.add(new_name)
            db.session.commit()
            return(redirect('/'))
        except:
            return("Something went wrong")
    else:
        names = Name.query.order_by(Name.id).all()
        return(render_template("index.html", names=names))

if __name__=="__main__":
    app.run(debug=True)
