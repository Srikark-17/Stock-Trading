import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

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

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Query database for user's stocks
    stocks = db.execute("SELECT symbol, shares FROM portfolios WHERE user_id = :user_id ORDER BY symbol DESC",
        user_id = session["user_id"])

    # Check if user has stocks
    if not stocks:
        return render_template("index.html", message = "Your portfolio is empty.")

    # Set total at 0
    total = 0

    # Add company name, current price and current stock value to stocks
    for stock in stocks:
        name = price = lookup(stock["symbol"])["name"]
        stock.update({"name": name})
        price = lookup(stock["symbol"])["price"]
        stock.update({"price": usd(price)})
        value = price * stock["shares"]
        stock.update({"value": usd(value)})
        total = total + value

    # Query database to get user's cash balance
    balance = db.execute("SELECT cash FROM users WHERE id = :user_id",
        user_id = session["user_id"])[0]["cash"]

    # Calculate stocks value grand total
    total = total + balance

    # Render homepage
    return render_template("index.html", stocks = stocks, balance = usd(balance), value = usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Assign inputs to variables
        ticker1_symbol = request.form.get("symbol")
        num_of_shares = request.form.get("shares")

        # Check if ticker symbol exists in the stock data
        if not lookup(ticker1_symbol):
            return apology("stock not found", 403)

        # Check if the user entered at least one share
        elif int(num_of_shares) <= 1:
            return apology("The number of shares entered has to be at least 1", 403)

        # Query database for how much cash user currently has
        user_balance = db.execute("SELECT cash FROM users WHERE id = :user_id",
            user_id = session["user_id"])[0]["cash"]

        # Calculate total price based on number of shares and stock's current price
        total_price = lookup(ticker1_symbol)["price"] * int(num_of_shares);

        # Check if user has enough cash based on stock's current price
        if total_price > user_balance:
            return apology("insufficient funds", 403)

        # Query database to insert transaction
        db.execute("INSERT INTO transactions (user_id, type, symbol, shares, price) VALUES (:user_id, :transaction_type, :symbol, :shares, :price)",
            user_id = session["user_id"],
            transaction_type = "purchase",
            symbol = ticker1_symbol,
            shares = int(num_of_shares),
            price = format(total_price, '.2f'))

        # Calculate user's new cash balance after purchase
        user_balance = user_balance - total_price

        # Query database to update user's cash balance
        db.execute("UPDATE users SET cash = :balance WHERE id = :user_id",
            user_id = session["user_id"],
            balance = user_balance)

        # Query database for user's portfolio
        portfolio = db.execute("SELECT shares FROM portfolios WHERE user_id = :user_id AND symbol = :symbol",
            user_id = session["user_id"],
            symbol = ticker1_symbol)

        # In case user already does have shares for purchased stock
        if len(portfolio) == 1:

            # Calculate new number of shares based on current amount and purchased amount
            shares = portfolio[0]["shares"] + int(num_of_shares)

            # Query database to update portfolios for newly purchased shares
            db.execute("UPDATE portfolios SET shares = :shares WHERE user_id = :user_id AND symbol = :symbol",
                user_id = session["user_id"],
                symbol = ticker1_symbol,
                shares = shares)

        # In case user doesn't already have shares for purchased stock
        else:
            # Query database to insert newly purchased shares info into portfolios
            db.execute("INSERT INTO portfolios (user_id, symbol, shares) VALUES (:user_id, :symbol, :shares)",
                user_id = session["user_id"],
                symbol = ticker1_symbol,
                shares = int(num_of_shares))

        # Get company name
        name = lookup(ticker1_symbol)["name"]

        # Flash info for the user
        flash(f"Purchased {num_of_shares} of {name}")

        # Redirect user to homepage
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
        # Query data for history of transactions
    transactions = db.execute("SELECT date, type, symbol, shares, price FROM transactions WHERE user_id = :user_id ORDER BY date DESC",
        user_id = session["user_id"])

    return render_template("history.html", transactions = transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Check if a username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Check if a password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
            username=request.form.get("username"))

        # Check if username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Assign inputs to variables
        ticker_symbol = request.form.get("symbol")

        # Check if a ticker symbol was given
        if not ticker_symbol:
            return apology("You must provide symbol", 403)

        # Check if the ticker symbol is valid
        elif not lookup(ticker_symbol):
            return apology("The stock was not found", 403)

        # Get quote info
        quote = lookup(ticker_symbol)

        # Format price to usd
        quote["price"] = usd(quote["price"])

        return render_template("quote1.html", quote = quote)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Variable Meanings
        # u = inputted username
        # p = inputted password
        # c = inputted confirmation

        # Assign inputs to variables
        u = request.form.get("username")
        p = request.form.get("password")
        c = request.form.get("confirmation")

        # Check if a username was submitted
        if not u:
            return apology("You must provide username", 403)

        # Check if a password was submitted
        elif not p:
            return apology("You must provide password", 403)

        # Check if a passwsord confirmation was submitted
        elif not c:
            return apology("You must provide password confirmation", 418)

        elif not p == c:
            return apology("Passwords must match", 418)

        # Query database for username
        username = db.execute("SELECT username FROM users WHERE username = :username"
        ,username = u)

        # Check if the username is not already taken
        if len(username) == 1:
            return apology("Sorry, this username has already been taken", 403)

        # Query database to insert new user
        else:
            new_user = db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)",
            username = u,
            password = generate_password_hash(p,
            method ="pbkdf2:sha256",
            salt_length = 8))

            if new_user:
                # Keep newly registered user logged in
                session["user_id"] = new_user

            # Flash info for the user
            flash(f"Registered as {u}")

            # Redirect user to homepage
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Assign inputs to variables
        input_symbol = request.form.get("symbol")
        input_shares = request.form.get("shares")

        # Check if a ticker symbol was submitted
        if not input_symbol:
            return apology("You must provide a ticker symbol", 403)

        # Check if the user is selling at least one shares
        elif int(input_shares) <= 1:
            return apology("The number of shares entered must be at least one in order to sell", 403)

        # Query database for user's portfolio
        stocks = db.execute("SELECT shares FROM portfolios WHERE user_id = :user_id AND symbol = :symbol",
            user_id = session["user_id"],
            symbol = input_symbol)

        # Check if the user has enough shares for selected symbol
        if len(stocks) != 1 or stocks[0]["shares"] < int(input_shares):
            return apology("not enough shares", 403)

        # Calculate total price based on number of shares and stock's current price
        price = lookup(input_symbol)["price"] * int(input_shares)

        # Query database to insert transaction
        db.execute("INSERT INTO transactions (user_id, type, symbol, shares, price) VALUES (:user_id, :transaction_type, :symbol, :shares, :price)",
            user_id = session["user_id"],
            transaction_type = "sell",
            symbol = input_symbol,
            shares = int(input_shares),
            price = format(price,".2f"))

        # Query database for how much cash user currently has
        balance = db.execute("SELECT cash FROM users WHERE id = :user_id",
                        user_id = session["user_id"])[0]["cash"]

        # Calculate user's new cash balance after purchase
        balance = balance + price

        # Query database to update user's cash balance
        db.execute("UPDATE users SET cash = :balance WHERE id = :user_id",
            user_id = session["user_id"],
            balance = balance)

        # Calculate new share amount
        shares = stocks[0]["shares"] - int(input_shares)

        # Query database to update user's portfolio
        db.execute("UPDATE portfolios SET shares = :shares WHERE user_id = :user_id AND symbol = :symbol",
            user_id = session["user_id"],
            symbol = input_symbol,
            shares = shares)

        # Get company name
        name = lookup(input_symbol)["name"]

        # Flash info for the user
        flash(f"Sold {input_shares} shares of {name}")

        # Redirect user to homepage
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        # Query database for stocks where user_id is equal to logged in user id
        stocks = db.execute("SELECT symbol FROM portfolios WHERE user_id =:user_id ORDER BY symbol ASC",
            user_id = session["user_id"])
        return render_template("sell.html", stocks = stocks)


@app.route("/add", methods=["GET", "POST"])
@login_required
def extracashs():
    """Adding more cash"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Assign input to variable
        input_amount = request.form.get("amount")

        # Ensure cash amount was submitted
        if not input_amount:
            return apology("You must provide an amount of cash to add", 403)

        # Query database to update user's cash amount
        db.execute("UPDATE users SET cash = cash + :amount WHERE id = :user_id",
            user_id = session["user_id"],
            amount = input_amount)

        # Flash info for the user
        flash(f"Added {usd(int(input_amount))} to your account")

        # Redirect user to homepage
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("wallet.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)