from flask import Flask, render_template, request 
from datetime import datetime

app = Flask(__name__)

@app.route("/", methods = ["GET", "POST"])
def home():
    age = None
    name = ""
    if request.method == "POST":
        name = request.form["name"]
        birth_year = int (request.form["birth_year"])
        current_year = datetime.now(). year
        age = current_year - birth_year
    return render_template("index.html", name = name, age = age)

if __name__ == "__main__":
    app.run(debug=True)