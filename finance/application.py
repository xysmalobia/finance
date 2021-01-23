import os

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
import sqlite3

from helpers import apology, login_required, lookup, usd

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


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Connect to sqlite3 database
connector = sqlite3.connect('finance.db')
connector.row_factory = sqlite3.Row
db = connector.cursor()

# Create tables
# db.execute('''CREATE TABLE users(id INT,username TEXT NOT NULL,hash TEXT NOT NULL,cash NUMERIC NOT NULL DEFAULT 10000.0, PRIMARY KEY(id));''')

# db.execute('''CREATE TABLE shares(symbol TEXT,name TEXT,user_id INT,total_share_count INT,current_price REAL);''')

# db.execute('''CREATE TABLE 'history'(symbol TEXT,name TEXT,user_id INT,transaction_share_count INT,original_price REAL,date datetime,purchase text);''')

# Make sure API key is set
# if not os.environ.get("API_KEY"):
    # raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # get user id from the session
    user_id = session["user_id"]

    # get user's current cash
    db.execute("SELECT * FROM users WHERE id = ?", [user_id])
    rows = db.fetchone()
    cash = float(rows['cash'])

    # display user's stocks, numbers of shares owned, current price of each stock, total value of each holding
    db.execute("SELECT symbol, name, total_share_count, current_price FROM shares WHERE user_id = ?", [user_id])
    stocks = db.fetchall()

    # update prices on db using lookup
    for stock in stocks:
        symbol = stock["symbol"]
        quotes = lookup(symbol)
        price = quotes["price"]

        db.execute("UPDATE shares SET current_price=:price WHERE symbol=:symbol",  {"price": price, "symbol": symbol})
        connector.commit()

    # calculate grand total (stock total value plus cash)
    db.execute("SELECT * FROM shares WHERE user_id = ?", [user_id])
    transaction_check = db.fetchall()

    if len(transaction_check) == 0:
        calc = float(cash)

    else:
        db.execute("SELECT SUM(total_share_count * current_price) FROM shares WHERE user_id = ?", [user_id])
        grand_total = db.fetchone()
        calc = float(grand_total["SUM(total_share_count * current_price)"]) + float(cash)

    return render_template("index.html", stocks=stocks, cash=cash, calc=calc)
    connector.commit()


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        # create variables
        symbol = request.form.get("symbol").upper()
        shares = int(request.form.get("shares"))

        # check if symbol has been provided
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        # check if share number provided
        if not request.form.get("shares"):
            return apology("must provide number of shares", 400)

        # Ensure share number is a positive integer
        if not shares > 0:
            return apology("must provide a positive integer", 400)

        # check current price using lookup
        quotes = lookup(symbol)

        # check if symbol exists in lookup
        if quotes == None:
            return apology("must provide valid stock symbol", 400)

        # if symbol exists get name and current price
        name = quotes["name"]
        price = float(quotes["price"])

        # get datetime
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

        # read out user id and cash
        user_id = session["user_id"]

        db.execute("SELECT cash FROM users WHERE id = ?", [user_id])
        row = db.fetchone()

        cash = float(row["cash"])
        total = float(price) * float(shares)
        updated_cash = float(cash) - float(total)

        # check if user has enough cash
        if total <= cash:

            # check whether shares already exist on database for this user
            db.execute("SELECT * FROM shares WHERE symbol=:symbol AND user_id=:user_id", {"symbol": symbol, "user_id": user_id})
            share_check = db.fetchall()

            if len(share_check) == 0:

                # insert shares into db
                db.execute("INSERT INTO shares (symbol, name, user_id, current_price, total_share_count) VALUES(?, ?, ?, ?, ?)",
                           (symbol, name, user_id, price, shares))
                db.execute("INSERT INTO history (symbol, name, user_id, original_price, transaction_share_count, date, purchase) VALUES(?, ?, ?, ?, ?, ?, 'BUY')",
                           (symbol, name, user_id, price, shares, dt_string))

            # if shares exist update the number of shares on db
            if len(share_check) > 0:
                db.execute("UPDATE shares SET total_share_count=(total_share_count + :shares) WHERE symbol=:symbol AND user_id=:user_id",
                           {"shares": shares, "symbol": symbol, "user_id": user_id})
                db.execute("INSERT INTO history (symbol, name, user_id, original_price, transaction_share_count, date, purchase) VALUES(?, ?, ?, ?, ?, ?, 'BUY')",
                           (symbol, name, user_id, price, shares, dt_string))

            # update user cash count
            db.execute("UPDATE users SET cash=:updated_cash WHERE id=:user_id", {"updated_cash": updated_cash, "user_id": user_id})

            flash ("Successfully bought shares.")
            return index()

        else:
            return apology("must provide sufficient funds", 400)

    if request.method == "GET":

        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # get user id from the session
    user_id = session["user_id"]

    # display user's stocks, numbers of shares owned, current price of each stock, total value of each holding
    db.execute("SELECT symbol, name, transaction_share_count, original_price, date, purchase FROM history WHERE user_id = ?", [user_id])
    stocks = db.fetchall()

    return render_template("history.html", stocks=stocks)


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
            connector.commit()

        # Ensure password is correct
        password = request.form.get("password")
        db.execute("SELECT hash FROM users WHERE username = ?", [username])
        row = db.fetchone()

        if not check_password_hash(row["hash"], password):
            return apology("invalid password", 403)
            connector.commit()

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
    connector.commit()

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
        connector.commit()

        flash ("Password changed.")

        # Redirect user to home page
        return redirect("/")

    elif request.method == "GET":

        # query user_id and username
        user_id = session["user_id"]
        db.execute("SELECT * FROM users WHERE id = ?", [user_id])
        row = db.fetchone()
        username = row["username"]

        connector.commit()

        return render_template("password.html", username=username)


@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    """add cash to user account"""

    if request.method == "POST":

        # create variables
        password = request.form.get("password")
        add_cash = float(request.form.get("add_cash"))

        # query user_id and username
        user_id = session["user_id"]

        # Ensure cash was submitted
        if not request.form.get("add_cash"):
            return apology("must provide an amount of cash", 400)

        # Ensure user entered a positive integer
        if not add_cash > 0:
            return apology("must provide a positive integer", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password matches database
        db.execute("SELECT hash FROM users WHERE id = ?", [user_id])
        row = db.fetchone()
        if not check_password_hash(row["hash"], password):
            return apology("must provide valid password", 400)
            connector.commit()

        # Update database with newly added cash
        db.execute("UPDATE users SET cash=(cash + :add_cash) WHERE id=:user_id", {"add_cash": add_cash, "user_id": user_id})
        connector.commit()

        flash ("Cash added.")

        # Redirect user to home page
        return redirect("/")

    elif request.method == "GET":

        # query user_id and username
        user_id = session["user_id"]
        db.execute("SELECT * FROM users WHERE id = ?", [user_id])
        row = db.fetchone()
        username = row["username"]

        return render_template("add_cash.html", username=username)


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    flash ("Logged out.")

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":

        symbol = request.form.get("symbol")

        # Ensure user enters a symbol
        if not request.form.get("symbol"):
            return apology("must provide stock symbol", 400)

        # Ensure user enters a valid symbol using lookup
        quotes = lookup(symbol)

        if quotes == None:
            return apology("must provide valid stock symbol", 400)

        name = quotes["name"]
        price = quotes["price"]
        return render_template("quoted.html", symbol=symbol, name=name, price=price)

    else:
        return render_template("quote.html")


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
            connector.commit()

        else:
            username = request.form.get("username")
            password = request.form.get("password")
            hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", (username, hash))
            connector.commit()

        flash ("Successfully registered user account.")

        # Redirect user to home page
        return redirect("/")

    elif request.method == "GET":
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        # get user id from the session
        user_id = session["user_id"]

        # get datetime
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

        # get user's current cash
        db.execute("SELECT cash FROM users WHERE id = ?", [user_id])
        row = db.fetchone()
        cash = float(row["cash"])

        # create variables from form input
        symbol = request.form.get("symbol").upper()
        shares = int(request.form.get("shares"))

        # get current share price with lookup
        quotes = lookup(symbol)
        name = quotes["name"]
        price = quotes["price"]

        # check if symbol has been provided
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        # check if symbol exists in lookup
        if quotes == None:
            return apology("must provide valid stock symbol", 400)

        # check if share number provided
        if not request.form.get("shares"):
            return apology("must provide number of shares", 400)

        # Ensure share number is a positive integer
        if not shares > 0:
            return apology("must provide a positive integer", 400)

        # check if shares exist in the db
        db.execute("SELECT * FROM shares WHERE symbol=:symbol AND user_id=:user_id", {"symbol": symbol, "user_id": user_id})
        stock_check = db.fetchall()

        if len(stock_check) == 0:
            return apology("must own stock to sell shares", 400)

        # check if user have enough shares to sell them
        db.execute("SELECT * FROM shares WHERE symbol=:symbol AND user_id=:user_id", {"symbol": symbol, "user_id": user_id})
        share_check = db.fetchall()

        if share_check[0]["total_share_count"] < shares:
            return apology("must own sufficient shares to sell them", 400)

        # update database with new share and cash counts and history
        db.execute("UPDATE shares SET total_share_count=(total_share_count - :shares) WHERE symbol=:symbol AND user_id=:user_id", {"shares": shares, "symbol": symbol, "user_id": user_id})
        db.execute("UPDATE users SET cash=(cash + (:price * :shares)) WHERE id=:user_id", {"price": price, "shares": shares, "user_id": user_id})
        db.execute("INSERT INTO history (symbol, name, user_id, original_price, transaction_share_count, date, purchase) VALUES(?, ?, ?, ?, ?, ?, 'SELL')",
                   (symbol, name, user_id, price, shares, dt_string))

        # remove stock from database if share count is 0
        db.execute("SELECT * FROM shares WHERE symbol=:symbol AND user_id=:user_id", {"symbol": symbol, "user_id": user_id})
        share_check = db.fetchall()

        if share_check[0]["total_share_count"] == 0:
            db.execute("DELETE FROM shares WHERE symbol=:symbol AND user_id=:user_id", {"symbol": symbol, "user_id": user_id})

        connector.commit()

        flash ("Successfully sold shares.")

        # recalculate values for updated index
        return index()

    else:
        return render_template("sell.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
