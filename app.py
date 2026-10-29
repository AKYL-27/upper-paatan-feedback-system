"""
Campus Vehicle Management System - Flask backend
--------------------------------------------------
Serves the existing static HTML pages (dashboard, user-management,
motorcycle-management, qrcode-management, entry-exit-records, reports,
register, login) and exposes a REST API for motorcycles, student/staff
registration, and security guard registration, backed by MongoDB.

Expected project layout (relative to this file):

    app.py
    .env                     # your secrets (do NOT commit this)
    index.html
    css/
    images/
    js/
    vendors/
    
    pages/
        admin-login.html
        user-management/users.html
        motorcycle-management/motorcycle.html
        entry-exit-records/entry-exit.html
        reports/reports.html
    uploads/
        orcr/                # created automatically at runtime
        student-dashboard/
                register.html
                login.html
                my-qrcode.html       # <-- lives here, not under pages/
                styles.css          # and any other assets register/login.html link to
        security-dashboard/
                login.html
                register.html
                dashboard.html
                profile.html

Run:
    pip install flask pymongo werkzeug python-dotenv --break-system-packages
    # On Windows, also: pip install tzdata --break-system-packages
    # make sure a MongoDB instance is running, e.g. mongod --dbpath ./data
    # Create a .env file next to this file with at least:
    #     MONGO_URI=...
    #     ADMIN_PASSWORD=your-strong-password   (first run only, creates the first admin)
    # Optional: FLASK_DEBUG=1 for local development (auto-reload + debugger).
    python app.py
"""


import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from bson import ObjectId
from bson.errors import InvalidId
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, request, send_from_directory
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import PyMongoError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# Load variables from a .env file (if present) into os.environ. This must run
# before any os.environ.get(...) call below.
load_dotenv()

# ── Configuration ────────────────────────────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads", "orcr")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Never hardcode real credentials here. Set MONGO_URI in your .env file.
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.environ.get("MONGO_DB", "motorcycle_system")

# Timezone used for "today" on the security dashboard. Set APP_TIMEZONE to change it.
LOCAL_TZ = ZoneInfo(os.environ.get("APP_TIMEZONE", "Asia/Manila"))

REQUIRED_FIELDS = ["owner", "plate", "brand", "model"]
# Registered / Pending / Flagged are the vehicle's gate-eligibility state.
# Approved / Declined are set from the motorcycle-management page's
# per-row Approve/Decline buttons (a moderation decision on the vehicle
# itself), distinct from a user/guard *account's* approval_status.
ALLOWED_STATUSES = {"Registered", "Pending", "Flagged", "Approved", "Declined"}

# QR pass status is tracked separately from the vehicle's gate-eligibility
# `status` above — this is purely about whether a QR pass has been issued
# for the vehicle (see the QR Code Management page).
ALLOWED_QR_STATUSES = {"Active", "None", "Expired"}

# Name is split into firstName / middleName (optional) / lastName. The full
# name is built server-side from those parts and stored as `fullName` so the
# rest of the app (motorcycle owner, dashboards, logs) keeps working.
# gradeLevel and section are required only for students (checked in
# validate_user_payload), since staff/faculty don't have them.
USER_REQUIRED_FIELDS = ["firstName", "lastName", "role", "idNumber", "email", "contactNumber", "password"]
ALLOWED_ROLES = {"student", "staff"}

# Security guard registration is a separate flow/collection from
# student & staff registration above, since guards don't have a
# grade level/section or an associated motorcycle.
SECURITY_REQUIRED_FIELDS = ["fullName", "idNumber", "email", "contactNumber", "password"]

ALLOWED_ORCR_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}
MAX_ORCR_SIZE_BYTES = 5 * 1024 * 1024  # 5MB, matches the frontend copy

app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = MAX_ORCR_SIZE_BYTES + (1 * 1024 * 1024)  # small buffer for form overhead

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
motorcycles = db["motorcycles"]
users = db["users"]
security_guards = db["security_guards"]
entry_exit_logs = db["entry_exit_logs"]
# Every scan that gets refused — an unrecognized QR code, or a gate-entry
# attempt on a motorcycle that isn't eligible or is already inside — is
# recorded here so the Reports page can chart denied/unverified attempts
# over time. This is separate from entry_exit_logs, which only holds
# successful entries/exits.
denied_scans = db["denied_scans"]
# Admin accounts for the admin dashboard (index.html and pages/*). Kept in
# their own collection, separate from students/staff and security guards.
admins = db["admins"]

# Enforce unique plate numbers and emails at the database level.
motorcycles.create_index("plate", unique=True)
users.create_index("email", unique=True)
security_guards.create_index("email", unique=True)
security_guards.create_index("idNumber", unique=True)
entry_exit_logs.create_index([("owner_id", 1), ("entry_time", -1)])
denied_scans.create_index("time")
admins.create_index("username", unique=True)


def seed_default_admin():
    """Create the first admin account if none exist yet.

    Reads ADMIN_USERNAME (default "admin"), ADMIN_PASSWORD (required) and
    ADMIN_EMAIL (optional) from the environment (or .env), so no password
    lives in the source code. Does nothing once any admin exists.
    """
    if admins.count_documents({}) > 0:
        return
    username = os.environ.get("ADMIN_USERNAME", "admin").strip().lower()
    password = os.environ.get("ADMIN_PASSWORD")
    if not password:
        print("[admin] No admin account exists. Set ADMIN_PASSWORD (and "
              "optionally ADMIN_USERNAME) in your .env file and restart to "
              "create the first admin.")
        return
    admins.insert_one({
        "username": username,
        "fullName": "Administrator",
        "email": os.environ.get("ADMIN_EMAIL", "").strip().lower(),
        "password_hash": generate_password_hash(password),
        "created_at": datetime.now(timezone.utc),
    })
    print(f"[admin] Created admin account '{username}'.")


seed_default_admin()


# ── Helpers ──────────────────────────────────────────────────────────────────
def serialize(doc):
    """Convert a MongoDB document into a JSON-friendly dict."""
    doc = dict(doc)
    doc["id"] = str(doc.pop("_id"))
    return doc


def to_object_id(raw_id):
    try:
        return ObjectId(raw_id)
    except (InvalidId, TypeError):
        return None


def validate_payload(data, partial=False):
    """Basic validation. Returns an error message, or None if valid."""
    if not partial:
        missing = [f for f in REQUIRED_FIELDS if not str(data.get(f, "")).strip()]
        if missing:
            return f"Missing required field(s): {', '.join(missing)}"

    if "status" in data and data["status"] not in ALLOWED_STATUSES:
        return f"Status must be one of: {', '.join(sorted(ALLOWED_STATUSES))}"

    if "qr_status" in data and data["qr_status"] not in ALLOWED_QR_STATUSES:
        return f"qr_status must be one of: {', '.join(sorted(ALLOWED_QR_STATUSES))}"

    return None


def clean_motorcycle_fields(data):
    """Pick out only the fields we care about and normalize them."""
    fields = {}
    for key in ["owner", "brand", "model", "color", "year", "orcr", "status", "qr_status"]:
        if key in data:
            fields[key] = str(data[key]).strip()
    if "plate" in data:
        fields["plate"] = str(data["plate"]).strip().upper()
    if "status" not in fields:
        fields.setdefault("status", "Registered")
    return fields


def _valid_email(email):
    return "@" in email and "." in email.split("@")[-1]


def validate_user_payload(data):
    missing = [f for f in USER_REQUIRED_FIELDS if not str(data.get(f, "")).strip()]
    if missing:
        return f"Missing required field(s): {', '.join(missing)}"

    email = str(data.get("email", "")).strip()
    if not _valid_email(email):
        return "Please provide a valid email address."

    if len(str(data.get("password", ""))) < 8:
        return "Password must be at least 8 characters."

    if data.get("role") not in ALLOWED_ROLES:
        return "Role must be 'student' or 'staff'."

    # Grade level and section only apply to students.
    if data.get("role") == "student":
        if not str(data.get("gradeLevel", "")).strip():
            return "Grade level is required for students."
        if not str(data.get("section", "")).strip():
            return "Section is required for students."

    return None


def validate_security_payload(data):
    missing = [f for f in SECURITY_REQUIRED_FIELDS if not str(data.get(f, "")).strip()]
    if missing:
        return f"Missing required field(s): {', '.join(missing)}"

    email = str(data.get("email", "")).strip()
    if not _valid_email(email):
        return "Please provide a valid email address."

    if len(str(data.get("password", ""))) < 8:
        return "Password must be at least 8 characters."

    return None


def approval_block_message(doc):
    """Return an error message if this account may not sign in yet, else None.

    Accounts created before approvals existed have no approval_status and are
    treated as approved.
    """
    status = doc.get("approval_status", "Approved")
    if status == "Pending":
        return "Your account is still waiting for approval. Please try again later."
    if status == "Declined":
        return "Your registration was declined. Please contact the security office."
    return None


def allowed_orcr_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_ORCR_EXTENSIONS


def _to_local(dt):
    """MongoDB returns naive datetimes that are really UTC. Make them local."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(LOCAL_TZ)


def serialize_log(doc):
    """Convert an entry/exit log document into a JSON-friendly, display-ready dict.

    MongoDB stores (and pymongo returns) these timestamps as naive UTC, so
    everything here is converted to LOCAL_TZ (Asia/Manila by default) before
    formatting or being handed to the frontend — otherwise both the display
    strings and the raw ISO timestamps are 8 hours off from PH time.
    """
    doc = dict(doc)
    doc["id"] = str(doc.pop("_id"))
    entry_time = doc.get("entry_time")
    exit_time = doc.get("exit_time")

    entry_local = _to_local(entry_time) if entry_time else None
    exit_local = _to_local(exit_time) if exit_time else None

    # Human-friendly display strings the history table can render directly.
    doc["date"] = entry_local.strftime("%b %d, %Y") if entry_local else ""
    doc["time_in"] = entry_local.strftime("%I:%M %p").lstrip("0") if entry_local else "—"
    doc["time_out"] = exit_local.strftime("%I:%M %p").lstrip("0") if exit_local else "—"

    # Raw ISO timestamps too (now with a local UTC+8 offset), in case the
    # frontend needs to do its own formatting or date-key comparisons.
    doc["entry_time"] = entry_local.isoformat() if entry_local else None
    doc["exit_time"] = exit_local.isoformat() if exit_local else None
    return doc


def build_log_query(args):
    query = {}

    owner_id = args.get("owner_id", "").strip()
    if owner_id:
        query["owner_id"] = owner_id

    q = args.get("q", "").strip()
    if q:
        regex = {"$regex": q, "$options": "i"}
        query["$or"] = [{"plate": regex}, {"status": regex}]

    date_str = args.get("date", "").strip()
    if date_str:
        try:
            # `date_str` is a calendar day in LOCAL_TZ (e.g. what a PH-based
            # <input type="date"> sends), but entry_time is stored as naive
            # UTC — so build the local day's bounds, then convert to naive
            # UTC to match what's actually in the database.
            local_day_start = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=LOCAL_TZ)
            local_day_end = local_day_start + timedelta(days=1)
            day_start = local_day_start.astimezone(timezone.utc).replace(tzinfo=None)
            day_end = local_day_end.astimezone(timezone.utc).replace(tzinfo=None)
            query["entry_time"] = {"$gte": day_start, "$lt": day_end}
        except ValueError:
            pass  # ignore unparseable date filters rather than erroring

    range_str = args.get("range", "").strip().lower()
    if range_str in ("week", "month") and "entry_time" not in query:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=7 if range_str == "week" else 30)
        query["entry_time"] = {"$gte": cutoff}

    return query


# ── Page routes (serve the existing static HTML) ────────────────────────────
@app.route("/")
def dashboard():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/admin/login")
def admin_login_page():
    # The login page lives in pages/. /pages/admin-login.html also works
    # directly; this is just a friendlier URL.
    return send_from_directory(os.path.join(BASE_DIR, "pages"), "admin-login.html")


@app.route("/dashboard")
def dashboard_page():
    # dashboard.html also lives in student-dashboard/, same reasoning as
    # /register and /login above.
    return redirect("/pages/student-dashboard/dashboard.html")


@app.route("/history")
def history_page():
    return redirect("/student-dashboard/history.html")


@app.route("/my-motorcycle")
def my_motorcycle_page():
    return redirect("/student-dashboard/my-motorcycle.html")


@app.route("/qrcode")
def qrcode_page():

    return redirect("/pages/student-dashboard/my-qrcode.html")


@app.route("/register")
def register_page():

    return redirect("/student-dashboard/register.html")


@app.route("/login")
def login_page():

    return redirect("/pages/student-dashboard/login.html")


@app.route("/security/register")
def security_register_page():
    return redirect("/security-dashboard/register.html")


@app.route("/security/login")
def security_login_page():
    return redirect("/security-dashboard/login.html")


@app.route("/pages/<path:subpath>")
def pages(subpath):
    return send_from_directory(os.path.join(BASE_DIR, "pages"), subpath)


# Static assets (css/js/vendors/images) are already handled automatically by
# Flask's static_folder="." configuration above.


# ── API: Motorcycles ─────────────────────────────────────────────────────────
@app.route("/api/motorcycles", methods=["GET"])
def list_motorcycles():
    q = request.args.get("q", "").strip()
    owner_id = request.args.get("owner_id", "").strip()

    query = {}
    if owner_id:
        query["owner_id"] = owner_id
    elif q:
        regex = {"$regex": q, "$options": "i"}
        query = {"$or": [{"owner": regex}, {"plate": regex}, {"brand": regex}, {"model": regex}]}

    docs = motorcycles.find(query).sort("created_at", -1)
    return jsonify([serialize(d) for d in docs])


@app.route("/api/motorcycles/<moto_id>", methods=["GET"])
def get_motorcycle(moto_id):
    oid = to_object_id(moto_id)
    if oid is None:
        return jsonify({"error": "Invalid motorcycle id"}), 400

    doc = motorcycles.find_one({"_id": oid})
    if doc is None:
        return jsonify({"error": "Motorcycle not found"}), 404
    return jsonify(serialize(doc))


@app.route("/api/motorcycles", methods=["POST"])
def create_motorcycle():
    data = request.get_json(silent=True) or {}
    error = validate_payload(data)
    if error:
        return jsonify({"error": error}), 400

    fields = clean_motorcycle_fields(data)
    fields["created_at"] = datetime.now(timezone.utc)
    fields["updated_at"] = fields["created_at"]

    try:
        result = motorcycles.insert_one(fields)
    except PyMongoError as exc:
        if "duplicate key" in str(exc).lower():
            return jsonify({"error": "Plate number already registered."}), 409
        return jsonify({"error": "Database error while saving motorcycle."}), 500

    doc = motorcycles.find_one({"_id": result.inserted_id})
    return jsonify(serialize(doc)), 201


@app.route("/api/motorcycles/<moto_id>", methods=["PUT", "PATCH"])
def update_motorcycle(moto_id):
    oid = to_object_id(moto_id)
    if oid is None:
        return jsonify({"error": "Invalid motorcycle id"}), 400

    data = request.get_json(silent=True) or {}
    error = validate_payload(data, partial=(request.method == "PATCH"))
    if error:
        return jsonify({"error": error}), 400

    fields = clean_motorcycle_fields(data)
    fields["updated_at"] = datetime.now(timezone.utc)

    try:
        doc = motorcycles.find_one_and_update(
            {"_id": oid},
            {"$set": fields},
            return_document=ReturnDocument.AFTER,
        )
    except PyMongoError as exc:
        if "duplicate key" in str(exc).lower():
            return jsonify({"error": "Plate number already registered."}), 409
        return jsonify({"error": "Database error while updating motorcycle."}), 500

    if doc is None:
        return jsonify({"error": "Motorcycle not found"}), 404
    return jsonify(serialize(doc))


@app.route("/api/motorcycles/<moto_id>", methods=["DELETE"])
def delete_motorcycle(moto_id):
    oid = to_object_id(moto_id)
    if oid is None:
        return jsonify({"error": "Invalid motorcycle id"}), 400

    result = motorcycles.delete_one({"_id": oid})
    if result.deleted_count == 0:
        return jsonify({"error": "Motorcycle not found"}), 404
    return jsonify({"deleted": True})


@app.route("/api/motorcycles/<moto_id>/orcr", methods=["POST"])
def upload_orcr(moto_id):
    """Upload / replace the OR/CR document for a motorcycle.

    Expects a multipart/form-data request with a single file field named
    'file'. Stores the file under uploads/orcr/<uuid>.<ext> and records the
    public path on the motorcycle document's 'orcr' field.
    """
    oid = to_object_id(moto_id)
    if oid is None:
        return jsonify({"error": "Invalid motorcycle id"}), 400

    moto = motorcycles.find_one({"_id": oid})
    if moto is None:
        return jsonify({"error": "Motorcycle not found"}), 404

    if "file" not in request.files:
        return jsonify({"error": "No file provided."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected."}), 400

    if not allowed_orcr_file(file.filename):
        return jsonify({"error": "File must be PNG, JPG, or PDF."}), 400

    ext = secure_filename(file.filename).rsplit(".", 1)[1].lower()
    stored_name = f"{uuid.uuid4().hex}.{ext}"
    stored_path = os.path.join(UPLOAD_DIR, stored_name)
    file.save(stored_path)

    public_path = f"/uploads/orcr/{stored_name}"

    doc = motorcycles.find_one_and_update(
        {"_id": oid},
        {"$set": {"orcr": public_path, "updated_at": datetime.now(timezone.utc)}},
        return_document=ReturnDocument.AFTER,
    )
    return jsonify(serialize(doc)), 200


@app.route("/uploads/orcr/<path:filename>")
def serve_orcr(filename):
    return send_from_directory(UPLOAD_DIR, filename)


# ── API: Registration (students / staff) ─────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register_user():
    data = request.get_json(silent=True) or {}
    error = validate_user_payload(data)
    if error:
        return jsonify({"error": error}), 400

    email = str(data["email"]).strip().lower()

    first_name = str(data["firstName"]).strip()
    middle_name = str(data.get("middleName", "")).strip()
    last_name = str(data["lastName"]).strip()
    # Build the display name from the parts so it can't drift out of sync.
    full_name = " ".join(p for p in (first_name, middle_name, last_name) if p)
    is_student = data["role"] == "student"

    user_doc = {
        "firstName": first_name,
        "middleName": middle_name,
        "lastName": last_name,
        "fullName": full_name,
        "role": data["role"],
        "idNumber": str(data["idNumber"]).strip(),
        "gradeLevel": str(data.get("gradeLevel", "")).strip() if is_student else "",
        "section": str(data.get("section", "")).strip() if is_student else "",
        "approval_status": "Pending",
        "email": email,
        "contactNumber": str(data["contactNumber"]).strip(),
        "password_hash": generate_password_hash(str(data["password"])),
        "created_at": datetime.now(timezone.utc),
    }

    try:
        result = users.insert_one(user_doc)
    except PyMongoError as exc:
        if "duplicate key" in str(exc).lower():
            return jsonify({"error": "An account with this email already exists."}), 409
        return jsonify({"error": "Database error while creating account."}), 500

    moto_result = None
    moto_data = data.get("motorcycle")
    if moto_data:
        # The frontend doesn't collect a separate "owner" field for the
        # motorcycle — it's implied by the account being registered. Fill it
        # in before validating, since validate_payload requires it.
        moto_data = dict(moto_data)
        moto_data.setdefault("owner", user_doc["fullName"])

        moto_error = validate_payload(moto_data)
        if moto_error:
            # Roll back the user if the motorcycle payload is invalid, so we
            # don't end up with an orphaned account.
            users.delete_one({"_id": result.inserted_id})
            return jsonify({"error": moto_error}), 400

        moto_fields = clean_motorcycle_fields(moto_data)
        moto_fields["owner"] = user_doc["fullName"]
        moto_fields["owner_id"] = str(result.inserted_id)
        moto_fields["status"] = "Pending"
        moto_fields["created_at"] = datetime.now(timezone.utc)
        moto_fields["updated_at"] = moto_fields["created_at"]

        try:
            moto_insert = motorcycles.insert_one(moto_fields)
            moto_result = serialize(motorcycles.find_one({"_id": moto_insert.inserted_id}))
        except PyMongoError as exc:
            users.delete_one({"_id": result.inserted_id})
            if "duplicate key" in str(exc).lower():
                return jsonify({"error": "Plate number already registered."}), 409
            return jsonify({"error": "Database error while saving motorcycle."}), 500

    user_response = serialize(users.find_one({"_id": result.inserted_id}))
    user_response.pop("password_hash", None)

    return jsonify({"user": user_response, "motorcycle": moto_result}), 201


@app.route("/api/login", methods=["POST"])
def login_user():
    data = request.get_json(silent=True) or {}
    identifier = str(data.get("identifier", "")).strip()
    password = str(data.get("password", ""))

    if not identifier or not password:
        return jsonify({"error": "ID/email and password are required."}), 400

    # The login form accepts either a student/employee ID or an email
    # address in the same field, so match against both.
    user = users.find_one({
        "$or": [
            {"email": identifier.lower()},
            {"idNumber": identifier},
        ]
    })
    # Use the same generic message whether the identifier doesn't exist or
    # the password is wrong, so we don't leak which accounts are registered.
    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Incorrect ID/email or password. Please try again."}), 401
    blocked = approval_block_message(user)
    if blocked:
        return jsonify({"error": blocked}), 403

    user_response = serialize(user)
    user_response.pop("password_hash", None)

    return jsonify({"user": user_response}), 200


@app.route("/api/users/<user_id>", methods=["GET"])
def get_user(user_id):
    oid = to_object_id(user_id)
    if oid is None:
        return jsonify({"error": "Invalid user id"}), 400

    user = users.find_one({"_id": oid})
    if user is None:
        return jsonify({"error": "User not found"}), 404

    user_response = serialize(user)
    user_response.pop("password_hash", None)
    return jsonify(user_response)


# ── API: Registration (security guards) ──────────────────────────────────────
@app.route("/api/security/register", methods=["POST"])
def register_security_guard():
    """Register a new security guard account.

    Kept separate from /api/register (students/staff) because guards don't
    have a grade level/section or a motorcycle to attach, and they live in
    their own collection so gate-side auth stays independent of the student
    system.
    """
    data = request.get_json(silent=True) or {}
    error = validate_security_payload(data)
    if error:
        return jsonify({"error": error}), 400

    email = str(data["email"]).strip().lower()
    id_number = str(data["idNumber"]).strip()

    guard_doc = {
        "fullName": str(data["fullName"]).strip(),
        "role": "security",
        "idNumber": id_number,
        "email": email,
        "contactNumber": str(data["contactNumber"]).strip(),
        "assignedPost": str(data.get("assignedPost", "")).strip(),
        "approval_status": "Pending",
        "password_hash": generate_password_hash(str(data["password"])),
        "created_at": datetime.now(timezone.utc),
    }

    try:
        result = security_guards.insert_one(guard_doc)
    except PyMongoError as exc:
        message = str(exc).lower()
        if "duplicate key" in message and "idnumber" in message:
            return jsonify({"error": "An account with this badge/employee ID already exists."}), 409
        if "duplicate key" in message:
            return jsonify({"error": "An account with this email already exists."}), 409
        return jsonify({"error": "Database error while creating account."}), 500

    guard_response = serialize(security_guards.find_one({"_id": result.inserted_id}))
    guard_response.pop("password_hash", None)

    return jsonify({"guard": guard_response}), 201


@app.route("/api/security/login", methods=["POST"])
def login_security_guard():
    data = request.get_json(silent=True) or {}
    identifier = str(data.get("identifier", "")).strip()
    password = str(data.get("password", ""))

    if not identifier or not password:
        return jsonify({"error": "ID/email and password are required."}), 400

    guard = security_guards.find_one({
        "$or": [
            {"email": identifier.lower()},
            {"idNumber": identifier},
        ]
    })
    if guard is None or not check_password_hash(guard["password_hash"], password):
        return jsonify({"error": "Incorrect ID/email or password. Please try again."}), 401
    blocked = approval_block_message(guard)
    if blocked:
        return jsonify({"error": blocked}), 403

    guard_response = serialize(guard)
    guard_response.pop("password_hash", None)

    return jsonify({"guard": guard_response}), 200


@app.route("/api/security/dashboard", methods=["GET"])
def security_dashboard():
    """Numbers and recent activity for the security dashboard.

    "Today" is based on LOCAL_TZ (default Asia/Manila), not UTC, so the
    counts reset at local midnight.

    NOTE: this route must stay above /api/security/<guard_id> below, or
    "dashboard" would be treated as a guard id.
    """
    try:
        limit = max(1, min(20, int(request.args.get("limit", 5))))
    except ValueError:
        limit = 5

    now_local = datetime.now(LOCAL_TZ)
    day_start = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    day_end = day_start + timedelta(days=1)
    yesterday_start = day_start - timedelta(days=1)

    entered_today = entry_exit_logs.count_documents(
        {"entry_time": {"$gte": day_start, "$lt": day_end}}
    )
    exited_today = entry_exit_logs.count_documents(
        {"exit_time": {"$gte": day_start, "$lt": day_end}}
    )
    entered_yesterday = entry_exit_logs.count_documents(
        {"entry_time": {"$gte": yesterday_start, "$lt": day_start}}
    )
    inside_now = entry_exit_logs.count_documents({"exit_time": None})

    # Each log can produce two events (an entry and, later, an exit).
    events = []
    for d in entry_exit_logs.find().sort("entry_time", -1).limit(limit):
        events.append((d["entry_time"], "entry", d))
    for d in (
        entry_exit_logs.find({"exit_time": {"$ne": None}})
        .sort("exit_time", -1)
        .limit(limit)
    ):
        events.append((d["exit_time"], "exit", d))
    events.sort(key=lambda e: _to_local(e[0]), reverse=True)
    events = events[:limit]

    # Look up owner names in one query.
    oids = [to_object_id(d.get("owner_id")) for _, _, d in events]
    oids = [o for o in oids if o is not None]
    names = {
        str(u["_id"]): u.get("fullName", "Unknown")
        for u in users.find({"_id": {"$in": oids}}, {"fullName": 1})
    }

    recent = [
        {
            "owner": names.get(d.get("owner_id"), "Unknown"),
            "plate": d.get("plate", ""),
            "time": _to_local(t).strftime("%I:%M %p").lstrip("0"),
            "type": kind,
        }
        for t, kind, d in events
    ]

    return jsonify({
        "entered_today": entered_today,
        "exited_today": exited_today,
        "inside_now": inside_now,
        "entered_delta": entered_today - entered_yesterday,
        "as_of": now_local.strftime("%I:%M %p").lstrip("0"),
        "recent": recent,
    })


@app.route("/api/security/<guard_id>", methods=["GET"])
def get_security_guard(guard_id):
    oid = to_object_id(guard_id)
    if oid is None:
        return jsonify({"error": "Invalid guard id"}), 400

    guard = security_guards.find_one({"_id": oid})
    if guard is None:
        return jsonify({"error": "Security guard not found"}), 404

    guard_response = serialize(guard)
    guard_response.pop("password_hash", None)
    return jsonify(guard_response)


@app.route("/api/security/<guard_id>/stats", methods=["GET"])
def security_guard_stats(guard_id):
    """How many vehicle entries this guard logged today and this month (local time)."""
    oid = to_object_id(guard_id)
    if oid is None:
        return jsonify({"error": "Invalid guard id"}), 400
    if security_guards.find_one({"_id": oid}, {"_id": 1}) is None:
        return jsonify({"error": "Security guard not found"}), 404

    now_local = datetime.now(LOCAL_TZ)
    day_start = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    month_start = day_start.replace(day=1)

    today = entry_exit_logs.count_documents(
        {"guard_id": guard_id, "entry_time": {"$gte": day_start}}
    )
    this_month = entry_exit_logs.count_documents(
        {"guard_id": guard_id, "entry_time": {"$gte": month_start}}
    )
    return jsonify({"today": today, "this_month": this_month})


@app.route("/api/security/<guard_id>/password", methods=["PATCH"])
def change_security_password(guard_id):
    """Change a guard's password. Requires the current password."""
    oid = to_object_id(guard_id)
    if oid is None:
        return jsonify({"error": "Invalid guard id"}), 400

    data = request.get_json(silent=True) or {}
    current_password = str(data.get("currentPassword", ""))
    new_password = str(data.get("newPassword", ""))

    if not current_password or not new_password:
        return jsonify({"error": "Current and new password are required."}), 400
    if len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters."}), 400

    guard = security_guards.find_one({"_id": oid})
    if guard is None:
        return jsonify({"error": "Security guard not found"}), 404
    if not check_password_hash(guard["password_hash"], current_password):
        return jsonify({"error": "Current password is incorrect."}), 401

    security_guards.update_one(
        {"_id": oid},
        {"$set": {"password_hash": generate_password_hash(new_password)}},
    )
    return jsonify({"updated": True})


# ── API: QR scanning (security) ──────────────────────────────────────────────
def find_motorcycle_from_code(code):
    """Resolve whatever a QR code contains to a motorcycle document.

    Accepts a JSON object ({"motorcycle_id": ...} / {"id": ...} / {"plate": ...}),
    a bare motorcycle id, a bare plate number, or a URL ending in either.
    """
    code = str(code or "").strip()
    if not code:
        return None

    ids, plates = [], []
    try:
        parsed = json.loads(code)
    except ValueError:
        parsed = None

    if isinstance(parsed, dict):
        for key in ("motorcycle_id", "motorcycleId", "id"):
            if parsed.get(key):
                ids.append(str(parsed[key]).strip())
        if parsed.get("plate"):
            plates.append(str(parsed["plate"]).strip().upper())
    else:
        token = code.rstrip("/").rsplit("/", 1)[-1]
        ids.append(token)
        plates.append(token.upper())

    for raw in ids:
        oid = to_object_id(raw)
        if oid is not None:
            doc = motorcycles.find_one({"_id": oid})
            if doc:
                return doc
    for plate in plates:
        doc = motorcycles.find_one({"plate": plate})
        if doc:
            return doc
    return None


@app.route("/api/scan/lookup", methods=["GET"])
def scan_lookup():
    """Look up the motorcycle, owner and in/out state for a scanned QR code."""
    code = request.args.get("code", "")
    moto = find_motorcycle_from_code(code)
    if moto is None:
        # An unrecognized QR code is itself a denied/unverified scan attempt
        # (e.g. an unregistered vehicle, a damaged code, or tampering), so
        # it's logged the same way refused entries/exits are below.
        denied_scans.insert_one({
            "code": code.strip()[:200],
            "plate": "",
            "reason": "unregistered",
            "time": datetime.now(timezone.utc),
        })
        return jsonify({"error": "No registered motorcycle matches this QR code."}), 404

    owner = None
    owner_oid = to_object_id(moto.get("owner_id"))
    if owner_oid is not None:
        owner = users.find_one({"_id": owner_oid}, {"fullName": 1, "role": 1, "idNumber": 1})

    open_record = entry_exit_logs.find_one({"plate": moto["plate"], "exit_time": None})

    return jsonify({
        "motorcycle": serialize(moto),
        "owner": {
            "name": (owner or {}).get("fullName") or moto.get("owner", "Unknown"),
            "role": (owner or {}).get("role", ""),
            "idNumber": (owner or {}).get("idNumber", ""),
        },
        "inside": open_record is not None,
    })


@app.route("/api/scan/confirm", methods=["POST"])
def scan_confirm():
    """Confirm a gate entry or exit for a scanned motorcycle.

    Body: {"motorcycle_id": "...", "action": "entry" | "exit", "guard_id": "..."}

    Rules:
      - Entry is only allowed for motorcycles with status "Registered"
        (Pending, Flagged and Declined are refused).
      - Entry is refused if the motorcycle is already inside.
      - Exit needs an open (still inside) record.
    """
    data = request.get_json(silent=True) or {}
    action = str(data.get("action", "")).strip().lower()
    guard_id = str(data.get("guard_id", "")).strip()

    if action not in ("entry", "exit"):
        return jsonify({"error": "Action must be 'entry' or 'exit'."}), 400

    moto_oid = to_object_id(data.get("motorcycle_id"))
    if moto_oid is None:
        return jsonify({"error": "Invalid motorcycle id."}), 400
    moto = motorcycles.find_one({"_id": moto_oid})
    if moto is None:
        return jsonify({"error": "Motorcycle not found."}), 404

    plate = moto["plate"]
    now = datetime.now(timezone.utc)

    if action == "entry":
        if moto.get("status") not in ("Registered", "Approved"):
            denied_scans.insert_one({
                "plate": plate,
                "reason": f"status_{moto.get('status', 'unknown')}",
                "time": now,
            })
            return jsonify({"error": f"Entry refused: motorcycle status is {moto.get('status', 'unknown')}."}), 403
        if entry_exit_logs.find_one({"plate": plate, "exit_time": None}):
            denied_scans.insert_one({
                "plate": plate,
                "reason": "already_inside",
                "time": now,
            })
            return jsonify({"error": "This motorcycle is already inside. Confirm an exit instead."}), 409

        doc = {
            "owner_id": moto.get("owner_id", ""),
            "plate": plate,
            "guard_id": guard_id,
            "entry_time": now,
            "exit_time": None,
            "status": "In Progress",
            "created_at": now,
        }
        result = entry_exit_logs.insert_one(doc)
        record = entry_exit_logs.find_one({"_id": result.inserted_id})
        return jsonify({"record": serialize_log(record), "action": "entry"}), 201

    record = entry_exit_logs.find_one_and_update(
        {"plate": plate, "exit_time": None},
        {"$set": {"exit_time": now, "status": "Completed", "exit_guard_id": guard_id}},
        sort=[("entry_time", -1)],
        return_document=ReturnDocument.AFTER,
    )
    if record is None:
        denied_scans.insert_one({
            "plate": plate,
            "reason": "no_open_entry",
            "time": now,
        })
        return jsonify({"error": "No open entry found for this motorcycle."}), 404
    return jsonify({"record": serialize_log(record), "action": "exit"}), 200


# ── API: Entry/Exit Records ──────────────────────────────────────────────────
@app.route("/api/entry-exit-records", methods=["GET"])
def list_entry_exit_records():
    """List entry/exit records, optionally scoped to one owner and filtered.

    Query params:
        owner_id  - restrict to one user's records
        q         - text search against plate or status
        date      - exact date filter, YYYY-MM-DD
        range     - "week" or "month", ignored if 'date' is also given
        page      - 1-indexed page number (default 1)
        page_size - records per page, max 100 (default 10)
    """
    query = build_log_query(request.args)

    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    try:
        page_size = max(1, min(100, int(request.args.get("page_size", 10))))
    except ValueError:
        page_size = 10

    total = entry_exit_logs.count_documents(query)
    docs = (
        entry_exit_logs.find(query)
        .sort("entry_time", -1)
        .skip((page - 1) * page_size)
        .limit(page_size)
    )
    records = [serialize_log(d) for d in docs]

    return jsonify({"records": records, "total": total, "page": page, "page_size": page_size})


@app.route("/api/entry-exit-records", methods=["POST"])
def create_entry_record():
    """Log a new gate entry (time_in = now, status = In Progress).

    Intended for the security/gate-scanning side of the app (e.g. an admin
    or kiosk scanning a QR code at the gate) rather than for students to
    call directly.
    """
    data = request.get_json(silent=True) or {}
    owner_id = str(data.get("owner_id", "")).strip()
    plate = str(data.get("plate", "")).strip().upper()

    if not owner_id or not plate:
        return jsonify({"error": "owner_id and plate are required."}), 400

    doc = {
        "owner_id": owner_id,
        "plate": plate,
        "guard_id": str(data.get("guard_id", "")).strip(),  # who scanned it (optional)
        "entry_time": datetime.now(timezone.utc),
        "exit_time": None,
        "status": "In Progress",
        "created_at": datetime.now(timezone.utc),
    }
    result = entry_exit_logs.insert_one(doc)
    return jsonify(serialize_log(entry_exit_logs.find_one({"_id": result.inserted_id}))), 201


@app.route("/api/entry-exit-records/<record_id>/exit", methods=["PATCH"])
def close_entry_record(record_id):
    """Mark an open record's exit time, completing it."""
    oid = to_object_id(record_id)
    if oid is None:
        return jsonify({"error": "Invalid record id"}), 400

    doc = entry_exit_logs.find_one_and_update(
        {"_id": oid, "exit_time": None},
        {"$set": {"exit_time": datetime.now(timezone.utc), "status": "Completed"}},
        return_document=ReturnDocument.AFTER,
    )
    if doc is None:
        return jsonify({"error": "Open (still-in-progress) record not found."}), 404
    return jsonify(serialize_log(doc))


@app.route("/api/security/logs", methods=["GET"])
def security_monitoring_logs():
    """Live feed of individual entry/exit events campus-wide, for the
    security Monitoring Logs page.

    Unlike /api/security/dashboard's 'recent' list (owner/plate/time/type
    only, for the small dashboard widget), this includes the motorcycle's
    make/model and the name of whichever guard scanned that specific event
    — entry and exit can be scanned by different guards, so guard_id and
    exit_guard_id are resolved separately per event.
    """
    try:
        limit = max(1, min(50, int(request.args.get("limit", 20))))
    except ValueError:
        limit = 20

    events = []
    for d in entry_exit_logs.find().sort("entry_time", -1).limit(limit):
        events.append((d["entry_time"], "entry", d))
    for d in (
        entry_exit_logs.find({"exit_time": {"$ne": None}})
        .sort("exit_time", -1)
        .limit(limit)
    ):
        events.append((d["exit_time"], "exit", d))
    events.sort(key=lambda e: _to_local(e[0]), reverse=True)
    events = events[:limit]

    owner_oids = [to_object_id(d.get("owner_id")) for _, _, d in events]
    owner_oids = [o for o in owner_oids if o is not None]
    owners = {
        str(u["_id"]): u.get("fullName", "Unknown")
        for u in users.find({"_id": {"$in": owner_oids}}, {"fullName": 1})
    }

    plates = list({d.get("plate", "") for _, _, d in events if d.get("plate")})
    motos = {
        m["plate"]: m
        for m in motorcycles.find({"plate": {"$in": plates}}, {"plate": 1, "brand": 1, "model": 1})
    }

    guard_ids = []
    for _, kind, d in events:
        gid = d.get("guard_id") if kind == "entry" else d.get("exit_guard_id")
        if gid:
            guard_ids.append(gid)
    guard_oids = [to_object_id(g) for g in guard_ids]
    guard_oids = [o for o in guard_oids if o is not None]
    guard_names = {
        str(g["_id"]): g.get("fullName", "Unknown")
        for g in security_guards.find({"_id": {"$in": guard_oids}}, {"fullName": 1})
    }

    logs = []
    for t, kind, d in events:
        plate = d.get("plate", "")
        moto = motos.get(plate, {})
        gid = d.get("guard_id") if kind == "entry" else d.get("exit_guard_id")
        logs.append({
            "owner": owners.get(d.get("owner_id"), "Unknown"),
            "plate": plate,
            "vehicle": f"{moto.get('brand', '')} {moto.get('model', '')}".strip(),
            "type": kind,
            "time": _to_local(t).strftime("%I:%M %p").lstrip("0"),
            "guard": guard_names.get(gid, "Unknown") if gid else "Unknown",
        })

    return jsonify({"logs": logs})


# ── API: Reports & Analytics ──────────────────────────────────────────────────
@app.route("/api/reports/summary", methods=["GET"])
def reports_summary():
    """Aggregated numbers for the Reports & Analytics page.

    Query params:
        days - how many trailing days (including today) to summarize.
               Clamped to 1-365, default 30.

    Returns daily entries/exits/denied-scan counts over the range, a
    24-hour scan-volume histogram over the range, an hour-by-hour "vehicles
    inside campus" snapshot for *today* (always today, regardless of
    'days'), a registration-status breakdown across all motorcycles, and a
    detailed 'records' list (date / owner / plate / brand / model / time in /
    time out) for the latest 1,000 entries in the range.
    """
    try:
        days = max(1, min(365, int(request.args.get("days", 30))))
    except ValueError:
        days = 30

    now_local = datetime.now(LOCAL_TZ)
    today_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    range_start_local = today_local - timedelta(days=days - 1)
    range_start_utc = range_start_local.astimezone(timezone.utc).replace(tzinfo=None)

    day_keys, day_labels = [], []
    for i in range(days):
        d = range_start_local + timedelta(days=i)
        day_keys.append(d.strftime("%Y-%m-%d"))
        day_labels.append(f"{d.strftime('%b')} {d.day}")

    entries_by_day = {k: 0 for k in day_keys}
    exits_by_day = {k: 0 for k in day_keys}
    denied_by_day = {k: 0 for k in day_keys}
    hour_counts = [0] * 24  # combined entry+exit scan volume, by hour of day

    for doc in entry_exit_logs.find({"entry_time": {"$gte": range_start_utc}}, {"entry_time": 1}):
        et = doc.get("entry_time")
        if not et:
            continue
        local = _to_local(et)
        key = local.strftime("%Y-%m-%d")
        if key in entries_by_day:
            entries_by_day[key] += 1
        hour_counts[local.hour] += 1

    for doc in entry_exit_logs.find({"exit_time": {"$gte": range_start_utc}}, {"exit_time": 1}):
        xt = doc.get("exit_time")
        if not xt:
            continue
        local = _to_local(xt)
        key = local.strftime("%Y-%m-%d")
        if key in exits_by_day:
            exits_by_day[key] += 1
        hour_counts[local.hour] += 1

    for doc in denied_scans.find({"time": {"$gte": range_start_utc}}, {"time": 1}):
        t = doc.get("time")
        if not t:
            continue
        local = _to_local(t)
        key = local.strftime("%Y-%m-%d")
        if key in denied_by_day:
            denied_by_day[key] += 1

    hour_labels = [datetime(2000, 1, 1, h).strftime("%I%p").lstrip("0") for h in range(24)]

    # "Vehicles inside" is always a snapshot of *today*, independent of the
    # days filter above — a 90-day trend line for it wouldn't mean much.
    start_hour, end_hour = 6, min(now_local.hour, 18)
    inside_hour_labels, inside_counts = [], []
    for h in range(start_hour, end_hour + 1):
        boundary_local = today_local.replace(hour=h)
        boundary_utc = boundary_local.astimezone(timezone.utc).replace(tzinfo=None)
        count = entry_exit_logs.count_documents({
            "entry_time": {"$lte": boundary_utc},
            "$or": [{"exit_time": None}, {"exit_time": {"$gt": boundary_utc}}],
        })
        inside_hour_labels.append(boundary_local.strftime("%I%p").lstrip("0"))
        inside_counts.append(count)

    active = motorcycles.count_documents({"status": {"$in": ["Registered", "Approved"]}})
    pending = motorcycles.count_documents({"status": "Pending"})
    flagged = motorcycles.count_documents({"status": {"$in": ["Flagged", "Declined"]}})

    # ── Detailed records: owner / brand / model per entry in range ──────────
    log_docs = list(
        entry_exit_logs.find({"entry_time": {"$gte": range_start_utc}})
        .sort("entry_time", -1)
        .limit(1000)
    )
    record_plates = list({d.get("plate", "") for d in log_docs if d.get("plate")})
    moto_map = {
        m["plate"]: m
        for m in motorcycles.find(
            {"plate": {"$in": record_plates}},
            {"plate": 1, "owner": 1, "brand": 1, "model": 1},
        )
    }
    owner_oids = [to_object_id(d.get("owner_id")) for d in log_docs if d.get("owner_id")]
    owner_oids = [o for o in owner_oids if o is not None]
    owner_names = {
        str(u["_id"]): u.get("fullName", "")
        for u in users.find({"_id": {"$in": owner_oids}}, {"fullName": 1})
    }

    records = []
    for d in log_docs:
        plate = d.get("plate", "")
        moto = moto_map.get(plate, {})
        entry_local = _to_local(d["entry_time"]) if d.get("entry_time") else None
        exit_local = _to_local(d["exit_time"]) if d.get("exit_time") else None
        records.append({
            "date": entry_local.strftime("%b %d, %Y") if entry_local else "",
            "owner": owner_names.get(d.get("owner_id")) or moto.get("owner", "Unknown"),
            "plate": plate,
            "brand": moto.get("brand", ""),
            "model": moto.get("model", ""),
            "time_in": entry_local.strftime("%I:%M %p").lstrip("0") if entry_local else "—",
            "time_out": exit_local.strftime("%I:%M %p").lstrip("0") if exit_local else "—",
        })

    return jsonify({
        "days": days,
        "day_labels": day_labels,
        "daily_entries": [entries_by_day[k] for k in day_keys],
        "daily_exits": [exits_by_day[k] for k in day_keys],
        "denied_counts": [denied_by_day[k] for k in day_keys],
        "hour_labels": hour_labels,
        "peak_hour_counts": hour_counts,
        "inside_hour_labels": inside_hour_labels,
        "inside_counts": inside_counts,
        "registration_status": {"active": active, "pending": pending, "flagged": flagged},
        "records": records,
    })


# ── API: Admin — login ───────────────────────────────────────────────────────
@app.route("/api/admin/login", methods=["POST"])
def login_admin():
    """Sign in an admin by username or email.

    Returns the admin's profile (never the password hash). The admin pages
    keep it in sessionStorage as 'adminUser'.
    """
    data = request.get_json(silent=True) or {}
    identifier = str(data.get("identifier", "")).strip().lower()
    password = str(data.get("password", ""))

    if not identifier or not password:
        return jsonify({"error": "Username/email and password are required."}), 400

    admin = admins.find_one({"$or": [{"username": identifier}, {"email": identifier}]})
    # Same generic message whether the account is missing or the password is
    # wrong, so we don't reveal which usernames exist.
    if admin is None or not check_password_hash(admin["password_hash"], password):
        return jsonify({"error": "Incorrect username/email or password."}), 401

    admin_response = serialize(admin)
    admin_response.pop("password_hash", None)
    admin_response.pop("created_at", None)
    return jsonify({"admin": admin_response}), 200


# ── API: Admin — user management & registration approval ────────────────────
ALLOWED_APPROVALS = {"Approved", "Declined"}


def _collection_for(kind):
    return {"user": users, "guard": security_guards}.get(kind)


def _iso_utc(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _admin_row(doc, kind):
    return {
        "id": str(doc["_id"]),
        "kind": kind,  # "user" (student/staff) or "guard" (security)
        "fullName": doc.get("fullName", ""),
        "firstName": doc.get("firstName", ""),
        "middleName": doc.get("middleName", ""),
        "lastName": doc.get("lastName", ""),
        "role": "security" if kind == "guard" else doc.get("role", ""),
        "idNumber": doc.get("idNumber", ""),
        "email": doc.get("email", ""),
        "contactNumber": doc.get("contactNumber", ""),
        "gradeLevel": doc.get("gradeLevel", ""),
        "section": doc.get("section", ""),
        "assignedPost": doc.get("assignedPost", ""),
        "approval_status": doc.get("approval_status", "Approved"),
        "created_at": _iso_utc(doc.get("created_at")),
    }


@app.route("/api/admin/users", methods=["GET"])
def admin_list_users():
    """All registered accounts (students, staff, security), newest first."""
    rows = [_admin_row(d, "user") for d in users.find()]
    rows += [_admin_row(d, "guard") for d in security_guards.find()]
    rows.sort(key=lambda r: r["created_at"] or "", reverse=True)
    return jsonify(rows)


@app.route("/api/admin/users/<kind>/<user_id>/approval", methods=["PATCH"])
def admin_set_approval(kind, user_id):
    """Approve or decline a registration.

    Body: {"status": "Approved" | "Declined"}
    Approving a student/staff account also approves that owner's Pending
    motorcycles (status -> Registered) so they can pass the gate scanner.
    """
    col = _collection_for(kind)
    oid = to_object_id(user_id)
    if col is None or oid is None:
        return jsonify({"error": "Invalid account."}), 400

    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in ALLOWED_APPROVALS:
        return jsonify({"error": "Status must be 'Approved' or 'Declined'."}), 400

    now = datetime.now(timezone.utc)
    doc = col.find_one_and_update(
        {"_id": oid},
        {"$set": {"approval_status": status, "reviewed_at": now}},
        return_document=ReturnDocument.AFTER,
    )
    if doc is None:
        return jsonify({"error": "Account not found."}), 404

    motorcycles_approved = 0
    if kind == "user" and status == "Approved":
        result = motorcycles.update_many(
            {"owner_id": user_id, "status": "Pending"},
            {"$set": {"status": "Registered", "updated_at": now}},
        )
        motorcycles_approved = result.modified_count

    return jsonify({
        "account": _admin_row(doc, kind),
        "motorcycles_approved": motorcycles_approved,
    })


@app.route("/api/admin/users/<kind>/<user_id>", methods=["DELETE"])
def admin_delete_user(kind, user_id):
    """Delete an account. For students/staff, their motorcycles are removed too."""
    col = _collection_for(kind)
    oid = to_object_id(user_id)
    if col is None or oid is None:
        return jsonify({"error": "Invalid account."}), 400

    result = col.delete_one({"_id": oid})
    if result.deleted_count == 0:
        return jsonify({"error": "Account not found."}), 404

    if kind == "user":
        motorcycles.delete_many({"owner_id": user_id})
    return jsonify({"deleted": True})


# ── Error handlers ───────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(413)
def file_too_large(_):
    return jsonify({"error": "File is too large. Max size is 5MB."}), 413


if __name__ == "__main__":
    # Debug mode exposes an interactive debugger, so it's off unless you opt in.
    # For local development, add FLASK_DEBUG=1 to your .env file.
    debug_mode = os.environ.get("FLASK_DEBUG", "0").strip().lower() in ("1", "true", "yes")
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
