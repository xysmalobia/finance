import os
import mysql.connector

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Connect to mysql database
connection = mysql.connector.connect('xysmalobia$default')
db = connection.cursor()

@app.route("/")
@login_required
def index():
    """Show frontpage with current reads"""

    # get user id from the session
    user_id = session["user_id"]

    # get sensor reads
    db.execute("SELECT * FROM sensor")
    rows = db.fetchall()

    return render_template("index.html", rows=rows)
    connection.commit()


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        username = request.form.get("username")
        db.execute("SELECT COUNT(username) FROM users WHERE username = ?", [username])

        # Ensure username exists
        if db.fetchone()[0] != 1:
            return apology("invalid username", 403)
            connection.commit()

        # Ensure password is correct
        password = request.form.get("password")
        db.execute("SELECT hash FROM users WHERE username = ?", [username])
        row = db.fetchone()

        if not check_password_hash(row["hash"], password):
            return apology("invalid password", 403)
            connection.commit()

        # Remember which user has logged in
        db.execute("SELECT * FROM users WHERE username = ?", [username])
        row = db.fetchall()
        session["user_id"] = row[0]["id"]

        # Flash alert
        flash ("Successfully logged in.")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """show user profile"""

    # query user_id and username
    user_id = session["user_id"]
    db.execute("SELECT * FROM users WHERE id = ?", [user_id])
    row = db.fetchone()
    username = row["username"]
    connection.commit()

    return render_template("profile.html", username=username)


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """change user password"""

    if request.method == "POST":

        # query user_id and username
        user_id = session["user_id"]
        db.execute("SELECT * FROM users WHERE id = ?", [user_id])
        row = db.fetchone()
        username = row["username"]

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirmatory password was submitted
        if not request.form.get("confirmation"):
            return apology("must provide password twice", 400)

        # Ensure password matches confirmation
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        password = request.form.get("password")
        hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        db.execute("UPDATE users SET hash=:hash WHERE id=:user_id", {"hash": hash, "user_id": user_id})
        connection.commit()

        flash ("Password changed.")

        # Redirect user to home page
        return redirect("/")

    elif request.method == "GET":

        # query user_id and username
        user_id = session["user_id"]
        db.execute("SELECT * FROM users WHERE id = ?", [user_id])
        row = db.fetchone()
        username = row["username"]

        connection.commit()

        return render_template("password.html", username=username)

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    flash ("Logged out.")

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached page via POST
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirmatory password was submitted
        if not request.form.get("confirmation"):
            return apology("must provide password twice", 400)

        # Ensure password matches confirmation
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # Ensure username is not taken
        username = request.form.get("username")
        db.execute("SELECT count(username) FROM users WHERE username = ?", [username])

        # if not taken add user to db
        if db.fetchone()[0] != 0:
            return apology("username is taken", 400)
            connection.commit()

        else:
            username = request.form.get("username")
            password = request.form.get("password")
            hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", (username, hash))
            connection.commit()

        flash ("Successfully registered user account.")

        # Redirect user to home page
        return redirect("/")

    elif request.method == "GET":
        return render_template("register.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
