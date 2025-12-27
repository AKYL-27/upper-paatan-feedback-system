from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv, find_dotenv
from datetime import datetime, timedelta
import os
from collections import Counter

# -----------------------------
# TIME HELPERS
# -----------------------------
def to_ampm(time_str):
    try:
        dt = datetime.strptime(time_str, "%H:%M")
    except ValueError:
        try:
            dt = datetime.strptime(time_str.strip(), "%I:%M %p")
        except ValueError:
            return time_str
    return dt.strftime("%I:%M %p").lstrip("0")

def to_24h(time_str):
    try:
        dt = datetime.strptime(time_str.strip(), "%I:%M %p")
        return dt.strftime("%H:%M")
    except ValueError:
        return time_str

# Load .env
load_dotenv(find_dotenv())

# Flask Setup
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev_secret")
app.jinja_env.filters['to_ampm'] = to_ampm

# MongoDB Setup
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "feedback_system")

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

# Collections
users_collection = db["users"]
document_requests_collection = db["document_requests"]
feedback_collection = db["feedback"]
document_types_collection = db["document_types"]

print(f"Connected to database: {DB_NAME}")


# -----------------------------
# LANDING PAGE / HOME ROUTE
# -----------------------------

@app.route("/")
def index():
    """Landing page redirects to admin login"""
    return redirect(url_for("admin_login"))

# -----------------------------
# ADMIN LOGIN ROUTES
# -----------------------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    # If already logged in, redirect to dashboard
    if "admin_user_id" in session:
        return redirect(url_for("admin_dashboard"))
    
    if request.method == "POST":
        email = request.form.get("email", "").lower().strip()
        password = request.form.get("password")
        remember_me = request.form.get("remember_me")

        # Validate input
        if not email or not password:
            flash("Please fill in all fields", "danger")
            return redirect(url_for("admin_login"))

        # Find user in database
        user = users_collection.find_one({"email": email})

        if not user:
            flash("Invalid email or password", "danger")
            return redirect(url_for("admin_login"))

        # Check if user is admin
        if user.get("role") != "admin":
            flash("Access denied. Admin credentials required.", "danger")
            return redirect(url_for("admin_login"))

        # Verify password
        if not check_password_hash(user["password"], password):
            flash("Invalid email or password", "danger")
            return redirect(url_for("admin_login"))

        # Set session
        session["admin_user_id"] = str(user["_id"])
        session["admin_user_name"] = f"{user.get('firstname','')} {user.get('lastname','')}".strip()
        session["admin_email"] = user["email"]
        
        # Set session permanent if remember me is checked
        if remember_me:
            session.permanent = True
            app.permanent_session_lifetime = timedelta(days=30)

        flash("Login successful! Welcome back.", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_user_id", None)
    session.pop("admin_user_name", None)
    session.pop("admin_email", None)
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("admin_login"))


@app.route("/admin/forgot-password", methods=["GET", "POST"])
def admin_forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").lower().strip()
        
        user = users_collection.find_one({"email": email, "role": "admin"})
        
        if user:
            # Here you would typically send a password reset email
            # For now, just show a success message
            flash("Password reset instructions have been sent to your email.", "success")
        else:
            # Don't reveal if email exists or not for security
            flash("If that email exists in our system, you will receive password reset instructions.", "info")
        
        return redirect(url_for("admin_login"))
    
    return render_template("admin-forgot-password.html")

# -----------------------------
# PROFILE ROUTES
# -----------------------------

@app.route("/admin/profile")
def admin_profile():
    if "admin_user_id" not in session:  # Changed from "user_id"
        return redirect(url_for("admin_login"))
    
    user_id = session["admin_user_id"]  # Changed from "user_id"
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    
    if not user:
        return redirect(url_for("admin_login"))
    
    return render_template("profile.html", user=user)


@app.route("/api/profile/update", methods=["POST"])
def update_profile():
    if "admin_user_id" not in session:  # Changed from "user_id"
        return jsonify({"success": False, "message": "Not authenticated"}), 401
    
    user_id = session["admin_user_id"]  # Changed from "user_id"
    data = request.get_json()
    
    # Get current user
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    
    # Check if email is being changed and if it's already taken
    new_email = data.get("email")
    if new_email and new_email != user["email"]:
        existing_user = users_collection.find_one({"email": new_email})
        if existing_user:
            return jsonify({"success": False, "message": "Email already in use"}), 400
    
    # Build update data
    update_data = {}
    if data.get("firstname"):
        update_data["firstname"] = data["firstname"]
    if data.get("lastname"):
        update_data["lastname"] = data["lastname"]
    if new_email:
        update_data["email"] = new_email
    
    # Update user
    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": update_data}
    )
    
    # Update session with new name if changed
    if "firstname" in update_data or "lastname" in update_data:
        session["admin_user_name"] = f"{update_data.get('firstname', user['firstname'])} {update_data.get('lastname', user['lastname'])}".strip()
    
    return jsonify({"success": True, "message": "Profile updated successfully"})


@app.route("/api/profile/change-password", methods=["POST"])
def change_password():
    if "admin_user_id" not in session:  # Changed from "user_id"
        return jsonify({"success": False, "message": "Not authenticated"}), 401
    
    user_id = session["admin_user_id"]  # Changed from "user_id"
    data = request.get_json()
    
    current_password = data.get("current_password")
    new_password = data.get("new_password")
    confirm_password = data.get("confirm_password")
    
    # Validate inputs
    if not current_password or not new_password or not confirm_password:
        return jsonify({"success": False, "message": "All fields are required"}), 400
    
    if new_password != confirm_password:
        return jsonify({"success": False, "message": "New passwords do not match"}), 400
    
    if len(new_password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters"}), 400
    
    # Get user
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    
    # Verify current password
    if not check_password_hash(user["password"], current_password):
        return jsonify({"success": False, "message": "Current password is incorrect"}), 400
    
    # Hash new password and update
    hashed_password = generate_password_hash(new_password)
    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"password": hashed_password}}
    )
    
    return jsonify({"success": True, "message": "Password changed successfully"})


# -----------------------------
# ADMIN SESSION PROTECTION
# -----------------------------

# Add this decorator to protect admin routes
from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin_user_id" not in session:
            flash("Please login to access this page", "warning")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/admin/dashboard")
def admin_dashboard():
    total_requests = document_requests_collection.count_documents({})
    pending = document_requests_collection.count_documents({"status": "Pending"})
    completed = document_requests_collection.count_documents({"status": "Completed"})
    avg_rating_pipeline = [
        {"$group": {"_id": None, "avg": {"$avg": "$rating"}}}
    ]
    avg_rating = list(feedback_collection.aggregate(avg_rating_pipeline))
    avg_rating_val = round(avg_rating[0]["avg"], 1) if avg_rating else 0
    return render_template("index.html",
                           total_requests=total_requests,
                           pending=pending,
                           completed=completed,
                           avg_rating=avg_rating_val)

@app.route("/admin/document-requests")
def document_requests():
    # Fetch all document requests, sorted by newest first
    requests = list(document_requests_collection.find().sort("request_date", -1))

    for req in requests:
        # User info
        if req.get("user_id"):
            user = users_collection.find_one({"_id": req["user_id"]})
            if user:
                req["user_name"] = f"{user.get('firstname', '')} {user.get('lastname', '')}".strip()
                req["user_email"] = user.get("email", "N/A")
            else:
                req["user_name"] = "N/A"
                req["user_email"] = "N/A"
        else:
            req["user_name"] = "N/A"
            req["user_email"] = "N/A"

        # Document type
        if req.get("document_type_id"):
            doc_type = document_types_collection.find_one({"_id": req["document_type_id"]})
            req["document_type_name"] = doc_type["name"] if doc_type else "N/A"
        else:
            req["document_type_name"] = "N/A"

        # Format dates for display
        req["request_date_formatted"] = req.get("request_date").strftime("%B %d, %Y %I:%M %p") if req.get("request_date") else "N/A"
        req["completed_date_formatted"] = req.get("completed_date").strftime("%B %d, %Y %I:%M %p") if req.get("completed_date") else "N/A"

        # Default remarks if empty
        req["remarks"] = req.get("remarks", "")

    # Fetch all users & document types for possible filters or modals
    users = list(users_collection.find())
    document_types = list(document_types_collection.find())

    return render_template(
        "document-requests.html",
        requests=requests,
        users=users,
        document_types=document_types
    )


@app.route("/admin/feedbacks")
def admin_feedbacks():
    return render_template("feedbacks.html")


@app.route("/admin/reports")
def admin_reports():
    return render_template("reports.html")




# -----------------------------
# DOCUMENT REQUESTS CRUD
# -----------------------------
# Create new request (AJAX)
@app.route("/api/request/create", methods=["POST"])
def api_create_request():
    data = request.json
    user_id = data.get("user_id")
    document_type_id = data.get("document_type_id")
    reason = data.get("reason")

    new_req = {
        "user_id": ObjectId(user_id) if user_id else None,
        "document_type_id": ObjectId(document_type_id) if document_type_id else None,
        "reason": reason,
        "status": "Pending",
        "request_date": datetime.now(),
        "completed_date": None,
        "remarks": ""
    }
    result = document_requests_collection.insert_one(new_req)
    return jsonify({"success": True, "request_id": str(result.inserted_id)})


# Update request status (Approve/Decline)
# Update request status with multi-step workflow
@app.route("/api/request/update/<request_id>", methods=["POST"])
def api_update_request(request_id):
    data = request.json
    action = data.get("action")  # approve, decline, ready, complete
    remarks = data.get("remarks", "")
    
    update_data = {"remarks": remarks}
    
    # Define status transitions based on action
    if action == "approve":
        update_data["status"] = "On Process"
    elif action == "decline":
        update_data["status"] = "Declined"
        update_data["completed_date"] = datetime.now()
    elif action == "ready":
        update_data["status"] = "Ready to Claim"
    elif action == "complete":
        update_data["status"] = "Completed"
        update_data["completed_date"] = datetime.now()
    
    document_requests_collection.update_one(
        {"_id": ObjectId(request_id)}, 
        {"$set": update_data}
    )
    return jsonify({"success": True})
    
@app.route("/api/list-requests")
def api_list_requests():
    requests = list(document_requests_collection.find().sort("request_date", -1))
    result = []

    for req in requests:
        # Requester (account that submitted the request)
        user_name = "N/A"
        if req.get("user_id"):
            user = users_collection.find_one({"_id": req["user_id"]})
            if user:
                user_name = f"{user.get('firstname','')} {user.get('lastname','')}".strip()

        # Student name (provided in the request)
        student_name = req.get("student_name", "N/A")

        # Document type (stored as string in request)
        document_type_name = req.get("document_type", "N/A")

        # Format request date
        request_date = req.get("request_date")
        request_date_formatted = request_date.strftime("%B %d, %Y") if request_date else "N/A"

        result.append({
            "_id": str(req["_id"]),
            "user_name": user_name,             # for admin table column: Requester
            "student_name": student_name,       # for admin table column: Student Name
            "document_type_name": document_type_name,
            "reason": req.get("reason", ""),
            "status": req.get("status", "Pending"),
            "request_date_formatted": request_date_formatted
        })

    return jsonify(result)

@app.route("/api/list-feedbacks")
def api_list_feedbacks():
    feedbacks = list(feedback_collection.find().sort("date_submitted", -1))
    result = []

    for fb in feedbacks:
        date = fb.get("date_submitted")
        formatted_date = date.strftime("%B %d, %Y %I:%M %p") if date else "N/A"

        result.append({
            "_id": str(fb["_id"]),
            "user_name": fb.get("user_name", "N/A"),
            "rating": fb.get("rating", 0),
            "comments": fb.get("comments", ""),
            "status": fb.get("status", "New"),
            "date_submitted": formatted_date
        })

    return jsonify(result)


@app.route("/feedback/delete/<feedback_id>", methods=["POST"])
def delete_feedback(feedback_id):
    feedback_collection.delete_one({"_id": ObjectId(feedback_id)})
    return redirect(url_for("feedbacks"))

# -----------------------------
# API ROUTES FOR REPORTS
# -----------------------------

# Document Requests count per type with filtering
@app.route("/api/reports/documents")
def api_reports_documents():
    from datetime import datetime, timedelta
    
    # Get filter parameters
    period = request.args.get('period', 'all')
    start_date = request.args.get('start')
    end_date = request.args.get('end')
    
    # Build match stage based on filters
    match_stage = {}
    
    if start_date and end_date:
        # Custom date range
        match_stage["request_date"] = {
            "$gte": datetime.fromisoformat(start_date),
            "$lte": datetime.fromisoformat(end_date + "T23:59:59.999")
        }
    elif period != 'all':
        # Predefined periods
        now = datetime.now()
        if period == 'today':
            start = datetime(now.year, now.month, now.day)
            match_stage["request_date"] = {"$gte": start}
        elif period == 'week':
            start = now - timedelta(days=now.weekday())
            start = datetime(start.year, start.month, start.day)
            match_stage["request_date"] = {"$gte": start}
        elif period == 'month':
            start = datetime(now.year, now.month, 1)
            match_stage["request_date"] = {"$gte": start}
        elif period == 'year':
            start = datetime(now.year, 1, 1)
            match_stage["request_date"] = {"$gte": start}
    
    # Build pipeline
    pipeline = []
    if match_stage:
        pipeline.append({"$match": match_stage})
    
    pipeline.append({"$group": {"_id": "$document_type", "count": {"$sum": 1}}})
    pipeline.append({"$sort": {"count": -1}})  # Sort by count descending
    
    result = list(document_requests_collection.aggregate(pipeline))
    
    # Format for chart.js
    data = {
        "labels": [r["_id"] for r in result], 
        "counts": [r["count"] for r in result]
    }
    return jsonify(data)


# Feedback ratings distribution with filtering
@app.route("/api/reports/feedbacks")
def report_feedbacks():
    from datetime import datetime, timedelta
    
    # Get filter parameters
    period = request.args.get('period', 'all')
    rating_filter = request.args.get('rating', 'all')
    start_date = request.args.get('start')
    end_date = request.args.get('end')
    
    # Build match stage based on filters
    match_stage = {}
    
    # Date filtering (using date_submitted field)
    if start_date and end_date:
        # Custom date range - include the entire end date
        match_stage["date_submitted"] = {
            "$gte": datetime.fromisoformat(start_date),
            "$lte": datetime.fromisoformat(end_date + "T23:59:59.999")
        }
    elif period != 'all':
        # Predefined periods
        now = datetime.now()
        if period == 'today':
            start = datetime(now.year, now.month, now.day)
            match_stage["date_submitted"] = {"$gte": start}
        elif period == 'week':
            start = now - timedelta(days=now.weekday())
            start = datetime(start.year, start.month, start.day)
            match_stage["date_submitted"] = {"$gte": start}
        elif period == 'month':
            start = datetime(now.year, now.month, 1)
            match_stage["date_submitted"] = {"$gte": start}
        elif period == 'year':
            start = datetime(now.year, 1, 1)
            match_stage["date_submitted"] = {"$gte": start}
    
    # Rating filtering
    if rating_filter != 'all':
        match_stage["rating"] = int(rating_filter)
    
    # Build pipeline
    pipeline = []
    if match_stage:
        pipeline.append({"$match": match_stage})
    
    pipeline.extend([
        {"$group": {"_id": "$rating", "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}
    ])
    
    data = list(feedback_collection.aggregate(pipeline))
    
    # Always keep 1–5 slots even if empty
    labels = ["1", "2", "3", "4", "5"]
    counts_map = {str(d["_id"]): d["count"] for d in data}
    counts = [counts_map.get(str(i), 0) for i in range(1, 6)]
    
    return jsonify({
        "labels": labels,
        "counts": counts
    })


@app.route("/api/reports/requests-per-month")
def requests_per_month():
    pipeline = [
        {"$group": {
            "_id": {"$month": "$request_date"},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}
    ]
    result = list(document_requests_collection.aggregate(pipeline))
    months = [r["_id"] for r in result]
    counts = [r["count"] for r in result]
    return jsonify({"months": months, "counts": counts})


@app.route("/api/reports/top-documents")
def top_documents():
    pipeline = [
        {"$group": {
            "_id": "$document_type_id",
            "count": {"$sum": 1}
        }},
        {"$sort": {"count": -1}}
    ]
    result = list(document_requests_collection.aggregate(pipeline))
    labels, values = [], []
    for r in result:
        doc = document_types_collection.find_one({"_id": ObjectId(r["_id"])})
        labels.append(doc["name"] if doc else "Unknown")
        values.append(r["count"])
    return jsonify({"labels": labels, "values": values})


@app.route("/api/reports/ratings")
def ratings_chart():
    pipeline = [
        {"$group": {
            "_id": "$rating",
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}
    ]
    result = list(feedback_collection.aggregate(pipeline))
    ratings = [r["_id"] for r in result]
    counts = [r["count"] for r in result]
    return jsonify({"ratings": ratings, "counts": counts})








# -----------------------------
# CLIENT ROUTES
# -----------------------------

@app.route("/client/login", methods=["GET", "POST"])
def client_login():
    if request.method == "POST":
        email = request.form.get("email", "").lower().strip()
        password = request.form.get("password")

        user = users_collection.find_one({"email": email})

        if not user:
            flash("User not found. Please check your email.", "danger")
            return redirect(url_for("client_login"))

        if not check_password_hash(user["password"], password):
            flash("Incorrect password. Please try again.", "danger")
            return redirect(url_for("client_login"))

        # Save session
        session["client_user_id"] = str(user["_id"])
        session["client_user_name"] = f"{user.get('firstname','')} {user.get('lastname','')}".strip()

        flash("Login successful!", "success")
        return redirect(url_for("client_home"))

    return render_template("client-login.html")

@app.route("/client/register", methods=["GET", "POST"])
def client_register():
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").lower().strip()
        password = request.form.get("password")

        # basic validation
        if not first_name or not last_name or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("client_register"))

        # check email exists
        if users_collection.find_one({"email": email}):
            flash("Email already exists", "danger")
            return redirect(url_for("client_register"))

        hashed = generate_password_hash(password)

        users_collection.insert_one({
            "firstname": first_name,
            "lastname": last_name,
            "email": email,
            "password": hashed,
            "role": "client"
        })

        flash("Account created successfully. Please login.", "success")
        return redirect(url_for("client_login"))

    return render_template("client-register.html")

# -----------------------------
# CLIENT ACCOUNT SETTINGS ROUTES
# -----------------------------

@app.route("/client/account-settings")
def client_account_settings():
    if "client_user_id" not in session:
        flash("Please login to access account settings", "warning")
        return redirect(url_for("client_login"))
    
    user_id = session["client_user_id"]
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    
    if not user:
        flash("User not found", "danger")
        return redirect(url_for("client_login"))
    
    return render_template("client-account-settings.html", user=user)


@app.route("/api/client/profile/update", methods=["POST"])
def update_client_profile():
    if "client_user_id" not in session:
        return jsonify({"success": False, "message": "Not authenticated"}), 401
    
    user_id = session["client_user_id"]
    data = request.get_json()
    
    # Get current user
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    
    # Check if email is being changed and if it's already taken
    new_email = data.get("email")
    if new_email and new_email != user["email"]:
        existing_user = users_collection.find_one({"email": new_email})
        if existing_user:
            return jsonify({"success": False, "message": "Email already in use"}), 400
    
    # Build update data
    update_data = {}
    if data.get("firstname"):
        update_data["firstname"] = data["firstname"]
    if data.get("lastname"):
        update_data["lastname"] = data["lastname"]
    if new_email:
        update_data["email"] = new_email
    
    # Update user
    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": update_data}
    )
    
    # Update session with new name if changed
    if "firstname" in update_data or "lastname" in update_data:
        session["client_user_name"] = f"{update_data.get('firstname', user['firstname'])} {update_data.get('lastname', user['lastname'])}".strip()
    
    return jsonify({"success": True, "message": "Profile updated successfully"})


@app.route("/api/client/profile/change-password", methods=["POST"])
def change_client_password():
    if "client_user_id" not in session:
        return jsonify({"success": False, "message": "Not authenticated"}), 401
    
    user_id = session["client_user_id"]
    data = request.get_json()
    
    current_password = data.get("current_password")
    new_password = data.get("new_password")
    confirm_password = data.get("confirm_password")
    
    # Validate inputs
    if not current_password or not new_password or not confirm_password:
        return jsonify({"success": False, "message": "All fields are required"}), 400
    
    if new_password != confirm_password:
        return jsonify({"success": False, "message": "New passwords do not match"}), 400
    
    if len(new_password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters"}), 400
    
    # Get user
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    
    # Verify current password
    if not check_password_hash(user["password"], current_password):
        return jsonify({"success": False, "message": "Current password is incorrect"}), 400
    
    # Hash new password and update
    hashed_password = generate_password_hash(new_password)
    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"password": hashed_password}}
    )
    
    return jsonify({"success": True, "message": "Password changed successfully"})


@app.route("/client/home")
def client_home():
    return render_template("client-home.html")

@app.route("/client/request-document")
def client_request_document():
    return render_template("request-document.html")

@app.route("/submit-request", methods=["POST"])
def submit_request():
    # Require login
    if "client_user_id" not in session:
        flash("Please login to submit a request.", "danger")
        return redirect(url_for("client_login"))

    # Get form data
    name = request.form.get("name", "").strip()
    document_type = request.form.get("document_type", "").strip()
    reason = request.form.get("reason", "").strip()

    # Validation
    if not name or not document_type or not reason:
        flash("All fields are required.", "danger")
        return redirect(url_for("client_request_document"))

    # Build request document
    new_request = {
        "user_id": ObjectId(session["client_user_id"]),
        "student_name": name,
        "document_type": document_type,
        "reason": reason,
        "status": "Pending",
        "request_date": datetime.now(),
        "completed_date": None,
        "remarks": ""
    }

    document_requests_collection.insert_one(new_request)

    flash("Your document request has been submitted successfully!", "success")
    return redirect(url_for("client_request_status"))


@app.route("/client/track-request")
def client_track_request():
    return render_template("track-request.html")

@app.route("/client/request-status")
def client_request_status():
    if "client_user_id" not in session:
        flash("Please login to view your requests.", "danger")
        return redirect(url_for("client_login"))

    user_id = ObjectId(session["client_user_id"])

    requests = list(document_requests_collection.find({
        "user_id": user_id
    }).sort("request_date", -1))   # newest first

    # Normalize fields for template
    for r in requests:
        r["_id"] = str(r["_id"])   # convert ObjectId to string
        r["created_at"] = r.get("request_date")  # match your HTML

    return render_template(
        "request-status.html",
        requests=requests
    )


@app.route("/client/feedback", methods=["GET", "POST"])
def client_feedback():
    if "client_user_id" not in session:
        flash("Please login to submit feedback.", "warning")
        return redirect(url_for("client_login"))

    user_id = session["client_user_id"]
    user = users_collection.find_one({"_id": ObjectId(user_id)})

    if request.method == "POST":
        rating = int(request.form.get("rating", 0))
        comments = request.form.get("comments", "")

        new_feedback = {
            "user_id": ObjectId(user_id),
            "user_name": f"{user.get('firstname','')} {user.get('lastname','')}".strip(),
            "rating": rating,
            "comments": comments,
            "date_submitted": datetime.now(),
            "status": "New"  # optional field
        }
        feedback_collection.insert_one(new_feedback)
        flash("Thank you for your feedback!", "success")
        return redirect(url_for("client_feedback_thank_you"))

    return render_template("client-feedback.html", user_name=f"{user.get('firstname','')} {user.get('lastname','')}".strip())

@app.route("/client/logout")
def client_logout():
    session.pop("client_user_id", None)
    session.pop("client_user_name", None)
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("client_login"))

@app.route("/visitor/feedback", methods=["GET", "POST"])
def visitor_feedback():
    if request.method == "POST":
        rating = int(request.form.get("rating", 0))
        comments = request.form.get("message", "")

        # Validation
        if not rating or rating < 1 or rating > 5:
            flash("Please select a rating.", "danger")
            return redirect(url_for("visitor_feedback"))

        new_feedback = {
            "user_id": None,  # No user ID for visitors
            "user_name": "Anonymous Visitor",
            "rating": rating,
            "comments": comments,
            "date_submitted": datetime.now(),
            "status": "New"
        }
        
        feedback_collection.insert_one(new_feedback)
        
        # Redirect to thank you page instead of back to form
        return redirect(url_for("visitor_feedback_thank_you"))

    return render_template("visitor-feedback.html", user_name="Visitor")


@app.route("/client/feedback/thank-you")
def client_feedback_thank_you():
    return render_template("client-feedback-thank-you.html")

@app.route("/visitor/feedback/thank-you")
def visitor_feedback_thank_you():
    return render_template("visitor-feedback-thank-you.html")

# -----------------------------
# RUN APP
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)
