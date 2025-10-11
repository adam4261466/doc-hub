import os
import uuid
import re
import stripe
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, jsonify, send_file
from werkzeug.utils import secure_filename, safe_join
from .models import User, File
from . import db, limiter
from flask_login import login_user, login_required, logout_user, current_user
from flask_limiter.util import get_remote_address
from limits import parse

from .document_processor import extract_text
from .faiss_index import FaissIndex
from .embeddings import EmbeddingGenerator


main = Blueprint("main", __name__)

# Stripe setup
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# -----------------------
# Home Route
# -----------------------
@main.route("/")
def home():
    return render_template("index.html", user=current_user)


# -----------------------
# Helpers
# -----------------------
ALLOWED_EXTENSIONS = {".txt", ".md", ".pdf"}
#ALLOWED_MIME_TYPES = {"text/plain", "text/markdown", "application/pdf"}

def allowed_file(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS

def check_storage_space(user_id, required_space=0):
    """Check if user has enough storage space. Returns (has_space, available_space_mb, used_space_mb)"""
    try:
        user = User.query.get(user_id)
        limit_mb = 1024.0 if user and user.is_pilot else 0.0  # 1GB for pilot, 0MB otherwise (no free tier)

        user_folder = os.path.join(current_app.config["UPLOAD_FOLDER"], str(user_id))
        if not os.path.exists(user_folder):
            return True, limit_mb, 0.0  # Assume limit available for new users

        # Calculate used space
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(user_folder):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    total_size += os.path.getsize(filepath)

        used_mb = total_size / (1024 * 1024)
        available_mb = limit_mb - used_mb

        has_space = available_mb >= (required_space / (1024 * 1024))
        return has_space, available_mb, used_mb
    except Exception as e:
        # If we can't check space, assume it's available
        limit_mb = 1024.0 if User.query.get(user_id) and User.query.get(user_id).is_pilot else 0.0
        return True, limit_mb, 0.0

def check_system_load():
    """Check if system is overloaded. Returns (is_overloaded, load_percentage)"""
    try:
        import psutil
        # Check CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        # Check memory usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent

        # Consider system overloaded if CPU > 90% or memory > 90%
        is_overloaded = cpu_percent > 90 or memory_percent > 90
        load_percentage = max(cpu_percent, memory_percent)
        return is_overloaded, load_percentage
    except ImportError:
        # psutil not available, assume not overloaded
        return False, 0.0
    except Exception as e:
        # If we can't check load, assume not overloaded
        return False, 0.0


# -----------------------
# Auth Routes
# -----------------------
from flask_mail import Message
from app import mail, csrf

@main.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        
        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for("main.register"))
        if User.query.filter_by(email=email).first():
            flash("Email already exists.", "danger")
            return redirect(url_for("main.register"))
        
        # ✅ Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # ✅ Send welcome email
        msg = Message(
            subject="Welcome to DocHub 🚀",
            recipients=[new_user.email]
        )
        msg.body = f"""
        Hi {new_user.username},

        Welcome to DocHub! 🎉  
        You’re all set to start your pilot.

        👉 Book your 30-min setup call here:  
        https://calendly.com/yourname/30min  

        Best,  
        The DocHub Team
        """

        try:
            mail.send(msg)
            flash("Registration successful! Please check your email for setup instructions.", "success")
        except Exception as e:
            flash(f"Registration successful, but email failed to send: {e}", "warning")

        return redirect(url_for("main.login"))

    return render_template("register.html")

# -----------------------
# Login Route with Brute-force protection
# -----------------------
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded

# Define limiter decorator
failed_login_limit = limiter.limit("5 per minute", key_func=get_remote_address)

@main.route("/login", methods=["GET", "POST"])
@failed_login_limit
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            if user.is_pilot:
                flash("Welcome back, Pilot user!", "success")
                return redirect(url_for("main.dashboard"))
            else:
                flash("Logged in successfully. Upgrade to Pilot for access to all features.", "info")
                return redirect(url_for("main.pricing"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")



@main.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for("main.login"))


@main.route("/create-checkout-session", methods=["POST"])
@login_required
@csrf.exempt
def create_checkout_session():
    try:
        success_url = url_for("main.payment_success", _external=True) + "?session_id={CHECKOUT_SESSION_ID}"
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "product_data": {
                        "name": "DocHub Pilot",
                    },
                    "unit_amount": 15000,  # $150
                },
                "quantity": 1,
            }],
            mode="payment",
            success_url=success_url,
            cancel_url=url_for("main.dashboard", _external=True),
            client_reference_id=str(current_user.id),
        )
        return redirect(checkout_session.url, code=303)
    except Exception as e:
        return jsonify(error=str(e)), 400


@main.route("/payment-success")
@login_required
def payment_success():
    session_id = request.args.get('session_id')
    if not session_id:
        flash("Payment verification failed. No session ID provided.", "danger")
        return redirect(url_for("main.pricing"))

    try:
        session = stripe.checkout.Session.retrieve(session_id)
        if session.payment_status == 'paid' and session.client_reference_id == str(current_user.id):
            if not current_user.is_pilot:
                current_user.is_pilot = True
                current_user.pilot_purchased_at = datetime.utcnow()
                db.session.commit()
                flash("Payment verified! Welcome to DocHub Pilot.", "success")
            else:
                flash("Welcome back, Pilot user!", "success")
            return redirect(url_for("main.dashboard"))
        else:
            flash("Payment verification failed. Please contact support.", "danger")
            return redirect(url_for("main.pricing"))
    except stripe.error.StripeError as e:
        flash(f"Stripe error: {str(e)}", "danger")
        return redirect(url_for("main.pricing"))
    except Exception as e:
        flash(f"Verification error: {str(e)}", "danger")
        return redirect(url_for("main.pricing"))


@main.route("/pricing")
@login_required
def pricing():
    return render_template("pricing.html", user=current_user)


@main.route("/webhook", methods=["POST"])
def stripe_webhook():
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    if not webhook_secret:
        return jsonify(error="Webhook secret not configured"), 500

    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError:
        return jsonify(error="Invalid payload"), 400
    except stripe.error.SignatureVerificationError:
        return jsonify(error="Invalid signature"), 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        user_id = session.get("client_reference_id")
        if user_id:
            user = User.query.get(int(user_id))
            if user:
                if not user.is_pilot:  # Idempotent update
                    user.is_pilot = True
                    user.pilot_purchased_at = datetime.utcnow()
                    db.session.commit()
                    print(f"Webhook updated user {user_id} to Pilot")  # Debug log
                else:
                    print(f"Webhook: User {user_id} already Pilot")  # Debug log

    return jsonify(success=True)


# -----------------------
# Dashboard + File Management
# -----------------------
@main.route("/dashboard")
@login_required
def dashboard():
    if not current_user.is_pilot:
        return redirect(url_for("main.pricing"))
    files_with_content = []
    for file in current_user.files:
        content = extract_text(file.path) if os.path.exists(file.path) else "No content available"
        files_with_content.append({
            "filename": file.filename,
            "size": file.size,
            "content": content,
            "id": file.id,
            "processed": file.processed
        })
    return render_template("dashboard.html", user=current_user, files=files_with_content, is_pilot=current_user.is_pilot)


@main.route("/upload", methods=["POST"])
@login_required
def upload():
    if not current_user.is_pilot:
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        return jsonify(success=False, error="Upgrade to Pilot to upload files.") if is_ajax else (flash("Upgrade to Pilot to upload files.", "warning"), redirect(url_for("main.pricing")))[1]

    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    try:
        # Check system load first
        is_overloaded, load_percentage = check_system_load()
        if is_overloaded:
            msg = f"System is currently overloaded ({load_percentage:.1f}% utilization). Please try again in a few minutes."
            return jsonify(success=False, error=msg) if is_ajax else (flash(msg, "danger"), redirect(url_for("main.dashboard")))[1]

        if "file" not in request.files:
            msg = "No file part"
            return jsonify(success=False, error=msg) if is_ajax else (flash(msg, "danger"), redirect(url_for("main.dashboard")))[1]

        f = request.files["file"]
        if f.filename == "":
            msg = "No selected file"
            return jsonify(success=False, error=msg) if is_ajax else (flash(msg, "danger"), redirect(url_for("main.dashboard")))[1]

        if not allowed_file(f.filename):
            msg = "Invalid file type. Only .txt, .md and .pdf allowed."
            return jsonify(success=False, error=msg) if is_ajax else (flash(msg, "danger"), redirect(url_for("main.dashboard")))[1]

        """if not allowed_mime_type(f):
            msg = "File content does not match the allowed type."
            return jsonify(success=False, error=msg) if is_ajax else (flash(msg, "danger"), redirect(url_for("main.dashboard")))[1]
"""
        # Check for special characters in filename
        if re.search(r'[^a-zA-Z0-9._\- ]', f.filename):
            flash("Filename contains special characters. It will be displayed as is, but ensure compatibility.", "warning")

        original_filename = f.filename  # Preserve Unicode and original filename
        ext = os.path.splitext(original_filename)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}{ext}"
        user_folder = os.path.join(current_app.config["UPLOAD_FOLDER"], str(current_user.id))
        os.makedirs(user_folder, exist_ok=True)
        filepath = os.path.join(user_folder, unique_filename)

        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(0)
        if size == 0:
            msg = "File is empty. Please upload a file with content."
            return jsonify(success=False, error=msg) if is_ajax else (flash(msg, "danger"), redirect(url_for("main.dashboard")))[1]
        if size > 16 * 1024 * 1024:
            msg = "File too large. Max size is 16 MB."
            return jsonify(success=False, error=msg) if is_ajax else (flash(msg, "danger"), redirect(url_for("main.dashboard")))[1]

        # Check file count limit (max 50 files per user, 200 for pilot)
        user_file_count = File.query.filter_by(user_id=current_user.id).count()
        max_files = 200 if current_user.is_pilot else 0
        if user_file_count >= max_files:
            msg = f"You have reached the maximum limit of {max_files} files. Please delete some files before uploading new ones."
            return jsonify(success=False, error=msg) if is_ajax else (flash(msg, "danger"), redirect(url_for("main.dashboard")))[1]

        # Check storage space
        has_space, available_mb, used_mb = check_storage_space(current_user.id, size)
        limit_mb = 1024.0 if current_user.is_pilot else 0.0
        if not has_space:
            msg = f"Storage limit exceeded. You have used {used_mb:.1f}MB of {limit_mb:.0f}MB. Available: {available_mb:.1f}MB. Upgrade to Pilot for access."
            return jsonify(success=False, error=msg) if is_ajax else (flash(msg, "danger"), redirect(url_for("main.dashboard")))[1]

        # Warn if storage is getting low (less than 10MB available)
        if available_mb < 10:
            flash(f"Warning: You have only {available_mb:.1f}MB of storage remaining. Consider deleting old files.", "warning")

        # Check for very large documents and suggest splitting
        if size > 5 * 1024 * 1024:  # 5MB
            flash(f"Large file detected ({size / (1024*1024):.1f}MB). Consider splitting large documents into smaller sections for better processing.", "info")

        f.save(filepath)
        if not os.path.exists(filepath):
            raise Exception("Failed to save file to disk")

        try:
            new_file = File(filename=original_filename, path=filepath, size=size, user_id=current_user.id)
            db.session.add(new_file)
            db.session.commit()
        except Exception as db_error:
            if 'filepath' in locals() and os.path.exists(filepath):
                try: os.remove(filepath)
                except: pass
            # Check if it's a database connection error
            if "connection" in str(db_error).lower() or "database" in str(db_error).lower():
                msg = "Database connection error. Please try again in a few moments. If the problem persists, contact support."
            else:
                msg = f"Upload failed: {str(db_error)}"
            return jsonify(success=False, error=msg) if is_ajax else (flash(msg, "danger"), redirect(url_for("main.dashboard")))[1]

        return jsonify(success=True, message="File uploaded successfully.") if is_ajax else (flash("File uploaded successfully.", "success"), redirect(url_for("main.dashboard")))[1]

    except Exception as e:
        if 'filepath' in locals() and os.path.exists(filepath):
            try: os.remove(filepath)
            except: pass
        # Check for system-level errors
        if "disk" in str(e).lower() or "space" in str(e).lower():
            msg = "Storage space is full. Please delete some files or contact support for storage upgrade."
        elif "permission" in str(e).lower():
            msg = "Permission denied. Please contact support if this persists."
        else:
            msg = f"Upload failed: {str(e)}"
        return jsonify(success=False, error=msg) if is_ajax else (flash(msg, "danger"), redirect(url_for("main.dashboard")))[1]


# -----------------------
# Process / Delete / View Routes
# -----------------------
@main.route("/process/<int:file_id>", methods=["POST"])
@login_required
def process_file_route(file_id):
    if not current_user.is_pilot:
        flash("Upgrade to Pilot to process files.", "warning")
        return redirect(url_for("main.pricing"))
    from .document_processor import process_file
    file = File.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    try:
        chunk_count = process_file(file.id, current_user.id, current_app.config["UPLOAD_FOLDER"])
        file.processed = True
        db.session.commit()
        flash(f"File processed into {chunk_count} chunks.", "success")
    except Exception as e:
        flash(f"Error processing file: {str(e)}", "danger")
    return redirect(url_for("main.dashboard"))


@main.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    if not current_user.is_pilot:
        flash("Upgrade to Pilot to delete files.", "warning")
        return redirect(url_for("main.pricing"))
    file = File.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    was_processed = file.processed
    for chunk in file.chunks:
        db.session.delete(chunk)
    if os.path.exists(file.path):
        os.remove(file.path)
    db.session.delete(file)
    db.session.commit()

    if was_processed:
        try:
            embedder = EmbeddingGenerator()
            faiss_index = FaissIndex(dim=embedder.get_dimension(), user_id=current_user.id)
            faiss_index.rebuild_index_from_chunks()
        except Exception as e:
            flash("File deleted but FAISS index rebuild failed. Some search results may be inaccurate.", "warning")

    flash("File deleted successfully.", "success")
    return redirect(url_for("main.dashboard"))


@main.route("/view-file/<path:filepath>")
@login_required
def view_file(filepath: str):
    user_folder = safe_join(current_app.config["UPLOAD_FOLDER"], str(current_user.id))
    full_path = safe_join(user_folder, filepath)
    if os.path.exists(full_path) and os.path.isfile(full_path):
        if not any(full_path.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
            flash("File type not allowed.")
            return redirect(url_for("main.dashboard"))
        return send_file(full_path, as_attachment=True, download_name=os.path.basename(filepath))
    flash("File not found.")
    return redirect(url_for("main.dashboard"))


# -----------------------
# Query Route with fallback and retry
# -----------------------
import time

@main.route("/query", methods=["POST"])
@limiter.limit("2 per minute")
@login_required
def query_documents():
    if not current_user.is_pilot:
        flash("Upgrade to Pilot to query documents.", "warning")
        return redirect(url_for("main.pricing"))
    from .document_processor import search_similar_chunks
    from transformers import pipeline

    query_text = request.form.get("query")
    if not query_text:
        flash("Please enter a query.", "danger")
        return redirect(url_for("main.dashboard"))

    # Check query length (max 1000 characters)
    max_query_length = 1000
    if len(query_text.strip()) > max_query_length:
        flash(f"Your query is too long ({len(query_text)} characters). Please shorten it to {max_query_length} characters or less. Consider breaking complex queries into smaller, focused questions.", "warning")
        return redirect(url_for("main.dashboard"))

    # Warn for very long queries (over 500 characters)
    if len(query_text.strip()) > 500:
        flash("Your query is quite long. For better results, consider making it more specific or breaking it into smaller questions.", "info")

    max_retries = 3
    retry_delay = 2  # seconds

    for attempt in range(max_retries):
        try:
            similar_chunks = search_similar_chunks(current_user.id, query_text, top_k=1)
            if not similar_chunks:
                flash("No relevant documents found for your query.", "info")
                return redirect(url_for("main.dashboard"))

            context = "\n\n".join([chunk['chunk'].text for chunk in similar_chunks])
            qa_pipeline = pipeline("question-answering", model="distilbert-base-cased-distilled-squad", device=-1)
            result = qa_pipeline(question=query_text, context=context, max_answer_length=500)
            answer = result.get('answer', 'No answer found')
            return render_template("query_results.html", user=current_user, query=query_text, answer=answer, supporting_chunks=similar_chunks)

        except Exception as e:
            error_msg = str(e).lower()
            if "model" in error_msg or "transformers" in error_msg or "pipeline" in error_msg:
                if attempt < max_retries - 1:
                    flash(f"AI model temporarily unavailable. Retrying... ({attempt + 1}/{max_retries})", "warning")
                    time.sleep(retry_delay)
                    continue
                else:
                    flash("AI model is currently unavailable after multiple attempts. Showing relevant documents instead.", "warning")
                    if 'similar_chunks' in locals() and similar_chunks:
                        answer = "I found these relevant documents that might answer your question:"
                        return render_template("query_results.html", user=current_user, query=query_text, answer=answer, supporting_chunks=similar_chunks)
                    flash("No relevant documents found and AI model failed.", "danger")
                    return redirect(url_for("main.dashboard"))
            else:
                # Non-model related error, don't retry
                flash(f"Query failed: {str(e)}", "danger")
                return redirect(url_for("main.dashboard"))

    # This should not be reached, but just in case
    flash("Query processing failed after all retries.", "danger")
    return redirect(url_for("main.dashboard"))


# -----------------------
# Admin Routes
# -----------------------
@main.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("main.dashboard"))
    users = User.query.filter_by(is_pilot=True).all()
    return render_template("admin_pilots.html", users=users)


@main.route("/reset_index/<int:user_id>", methods=["POST"])
@csrf.exempt
@login_required
def reset_index(user_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("main.admin"))
    try:
        embedder = EmbeddingGenerator()
        faiss_index = FaissIndex(dim=embedder.get_dimension(), user_id=user_id)
        faiss_index.rebuild_index_from_chunks()
        flash(f"Index reset for user {user_id}.", "success")
    except Exception as e:
        flash(f"Error resetting index: {str(e)}", "danger")
    return redirect(url_for("main.admin"))


@main.route("/toggle-pilot/<int:user_id>", methods=["POST"])
@csrf.exempt
@login_required
def toggle_pilot(user_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("main.admin"))
    user = User.query.get_or_404(user_id)
    user.is_pilot = not user.is_pilot
    db.session.commit()
    flash(f"Pilot status for {user.username} updated.", "success")
    return redirect(url_for("main.admin"))


@main.route("/user-stats/<int:user_id>")
@login_required
def user_stats(user_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("main.admin"))
    user = User.query.get_or_404(user_id)
    file_count = File.query.filter_by(user_id=user.id).count()
    has_space, available_mb, used_mb = check_storage_space(user.id)
    return render_template("admin_user_stats.html", user=user, file_count=file_count, used_mb=used_mb, available_mb=available_mb)


@main.route("/impersonate/<int:user_id>", methods=["POST"])
@csrf.exempt
@login_required
def impersonate(user_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("main.admin"))
    user = User.query.get_or_404(user_id)
    # Store admin id in session for return
    from flask import session
    session['admin_id'] = current_user.id
    login_user(user)
    flash(f"You are now impersonating {user.username}.", "info")
    return redirect(url_for("main.dashboard"))


@main.route("/return-to-admin")
@login_required
def return_to_admin():
    from flask import session
    admin_id = session.get('admin_id')
    if admin_id:
        admin_user = User.query.get(admin_id)
        if admin_user and admin_user.is_admin:
            login_user(admin_user)
            session.pop('admin_id', None)
            flash("Returned to admin account.", "info")
            return redirect(url_for("main.admin"))
    flash("Unable to return to admin.", "danger")
    return redirect(url_for("main.dashboard"))


@main.route("/delete-user/<int:user_id>", methods=["POST"])
@csrf.exempt
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("main.admin"))
    user = User.query.get_or_404(user_id)
    # Delete files and chunks
    for file in user.files:
        for chunk in file.chunks:
            db.session.delete(chunk)
        if os.path.exists(file.path):
            os.remove(file.path)
        db.session.delete(file)
    # Delete user's uploads folder
    import shutil
    user_folder = os.path.join("data", "uploads", str(user_id))
    if os.path.exists(user_folder):
        shutil.rmtree(user_folder)
    # Delete FAISS index folder
    faiss_dir = os.path.join("data", "faiss", f"{user_id}.faiss")
    if os.path.exists(faiss_dir):
        shutil.rmtree(faiss_dir)
    db.session.delete(user)
    db.session.commit()
    flash("User and their data deleted.", "danger")
    return redirect(url_for("main.admin"))


@main.route("/system-stats")
@login_required
def system_stats():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("main.admin"))
    user_count = User.query.count()
    pilot_count = User.query.filter_by(is_pilot=True).count()
    file_count = File.query.count()
    chunk_count = Chunk.query.count()
    # Calculate total storage used
    total_used = 0
    for file in File.query.all():
        total_used += file.size
    total_used_mb = total_used / (1024 * 1024)
    return render_template("admin_stats.html", user_count=user_count, pilot_count=pilot_count, file_count=file_count, chunk_count=chunk_count, total_used_mb=total_used_mb)


# -----------------------
# Error Handlers
# -----------------------
@main.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@main.errorhandler(500)
def internal_server_error(e):
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(success=False, error="Internal server error"), 500
    return render_template("500.html"), 500
