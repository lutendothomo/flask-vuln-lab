with open("app.py", encoding="utf-8") as f:
    content = f.read()

old = '''@app.route("/bookings", methods=["GET", "POST"])
def bookings():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()

    if request.method == "POST":
        client_name = request.form["client_name"].strip()
        pickup_location = request.form["pickup_location"].strip()
        delivery_location = request.form["delivery_location"].strip()
        notes = request.form.get("notes", "").strip()
        db.execute(
            """INSERT INTO bookings
               (user_id, client_name, pickup_location, delivery_location, notes, payment_status, delivery_status)
               VALUES (?, ?, ?, ?, ?, 'Pending', 'Pending Dispatch')""",
            (session["user_id"], client_name, pickup_location, delivery_location, notes),
        )
        db.commit()

    search = request.args.get("q", "")'''

new = '''def validate_booking_fields(client_name, pickup_location, delivery_location, notes):
    if not client_name or len(client_name) > 100:
        return "Client name is required and must be 100 characters or fewer."
    if not pickup_location or len(pickup_location) > 200:
        return "Pickup location is required and must be 200 characters or fewer."
    if not delivery_location or len(delivery_location) > 200:
        return "Delivery location is required and must be 200 characters or fewer."
    if len(notes) > 500:
        return "Booking notes must be 500 characters or fewer."
    return None


@app.route("/bookings", methods=["GET", "POST"])
def bookings():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()

    error = None
    if request.method == "POST":
        client_name = request.form["client_name"].strip()
        pickup_location = request.form["pickup_location"].strip()
        delivery_location = request.form["delivery_location"].strip()
        notes = request.form.get("notes", "").strip()
        error = validate_booking_fields(client_name, pickup_location, delivery_location, notes)
        if not error:
            db.execute(
                """INSERT INTO bookings
                   (user_id, client_name, pickup_location, delivery_location, notes, payment_status, delivery_status)
                   VALUES (?, ?, ?, ?, ?, 'Pending', 'Pending Dispatch')""",
                (session["user_id"], client_name, pickup_location, delivery_location, notes),
            )
            db.commit()

    search = request.args.get("q", "")'''

assert content.count(old) == 1, "bookings() didn't match exactly — paste me app.py's bookings() function"
content = content.replace(old, new)

old2 = 'return render_template("bookings.html", bookings=all_bookings, username=session["username"], search=search)'
new2 = '''return render_template(
        "bookings.html", bookings=all_bookings, username=session["username"], search=search, error=error
    )'''
assert content.count(old2) == 1, "final render_template call didn't match"
content = content.replace(old2, new2)

with open("app.py", "w", encoding="utf-8") as f:
    f.write(content)

print("patched app.py")