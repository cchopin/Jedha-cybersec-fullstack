import os

import psycopg2
from flask import Flask, flash, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "swarmitsecret")

# Database configuration
db_user = os.environ.get("POSTGRES_USER", "postgres")
db_password = os.environ.get("POSTGRES_PASSWORD", "postgres")
db_host = os.environ.get("POSTGRES_HOST", "db")
db_port = os.environ.get("POSTGRES_PORT", "5432")
db_name = os.environ.get("POSTGRES_DB", "hive_directory")

# SQLAlchemy configuration
app.config["SQLALCHEMY_DATABASE_URI"] = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Employee model
class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    
    def __repr__(self):
        return f"<Employee {self.name}>"

# Routes
@app.route("/")
def index():
    employees = Employee.query.all()
    return render_template("index.html", employees=employees)

@app.route("/add", methods=["GET", "POST"])
def add_employee():
    if request.method == "POST":
        name = request.form["name"]
        role = request.form["role"]
        email = request.form["email"]
        phone = request.form["phone"]
        
        new_employee = Employee(name=name, role=role, email=email, phone=phone)
        db.session.add(new_employee)
        db.session.commit()
        
        flash("Employee added successfully!")
        return redirect(url_for("index"))
    
    return render_template("add.html")

@app.route("/delete/<int:id>")
def delete_employee(id):
    employee = Employee.query.get_or_404(id)
    db.session.delete(employee)
    db.session.commit()
    
    flash("Employee deleted successfully!")
    return redirect(url_for("index"))

# Create tables
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
