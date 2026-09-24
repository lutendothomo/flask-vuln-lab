content = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <h1>Bookings</h1>

  {% if error %}<div class="error">{{ error }}</div>{% endif %}

  <form method="get" class="inline">
    <input name="q" placeholder="Search by client name..." value="{{ search }}">
    <button type="submit">Search</button>
  </form>

  <form method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input name="client_name" placeholder="Client name" maxlength="100" required>
    <input name="pickup_location" placeholder="Pickup location" maxlength="200" required>
    <input name="delivery_location" placeholder="Delivery location" maxlength="200" required>
    <textarea name="notes" placeholder="Booking notes (optional)" maxlength="500"></textarea>
    <button type="submit">Create booking</button>
  </form>

  <ul class="booking-list">
    {% for booking in bookings %}
      <li class="booking-card">
        <div class="route">{{ booking["pickup_location"] }} &rarr; {{ booking["delivery_location"] }}</div>
        <div class="client">Client: {{ booking["client_name"] }}</div>
        {% if booking["notes"] %}<div class="notes-text">{{ booking["notes"] }}</div>{% endif %}

        <span class="badge {{ "paid" if booking["payment_status"] == "Paid" else "pending" }}">{{ booking["payment_status"] }}</span>
        <span class="badge {{ "delivered" if booking["delivery_status"] == "Delivered" else ("transit" if booking["delivery_status"] == "In Transit" else ("delayed" if booking["delivery_status"] == "Delayed" else "pending")) }}">{{ booking["delivery_status"] }}</span>

        <form method="post" action="{{ url_for('update_status', booking_id=booking['id']) }}" class="status-form">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <select name="payment_status">
            {% for status in ["Pending", "Paid", "Refunded"] %}
              <option value="{{ status }}" {% if booking["payment_status"] == status %}selected{% endif %}>{{ status }}</option>
            {% endfor %}
          </select>
          <select name="delivery_status">
            {% for status in ["Pending Dispatch", "In Transit", "Delivered", "Delayed"] %}
              <option value="{{ status }}" {% if booking["delivery_status"] == status %}selected{% endif %}>{{ status }}</option>
            {% endfor %}
          </select>
          <button type="submit">Update</button>
        </form>
      </li>
    {% endfor %}
  </ul>
</div>
{% endblock %}
'''

with open("templates/bookings.html", "w", encoding="utf-8") as f:
    f.write(content)

print("patched bookings.html")