import os
import uuid
import re
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
        user_folder = os.path.join(current_app.config["UPLOAD_FOLDER"], str(user_id))
        if not os.path.exists(user_folder):
            return True, 100.0, 0.0  # Assume 100MB available for new users

        # Calculate used space
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(user_folder):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    total_size += os.path.getsize(filepath)

        used_mb = total_size / (1024 * 1024)
        available_mb = 100.0 - used_mb  # Assume 100MB per user limit

        has_space = available_mb >= (required_space / (1024 * 1024))
        return has_space, available_mb, used_mb
    except Exception as e:
        # If we can't check space, assume it's available
        return True, 100.0, 0.0

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
        
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
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
            flash("Logged in successfully.", "success")
            return redirect(url_for("main.dashboard"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")



@main.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for("main.login"))


# -----------------------
# Dashboard + File Management
# -----------------------
@main.route("/dashboard")
@login_required
def dashboard():
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
    return render_template("dashboard.html", user=current_user, files=files_with_content)


@main.route("/upload", methods=["POST"])
@login_required
def upload():
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

        # Check file count limit (max 50 files per user)
        user_file_count = File.query.filter_by(user_id=current_user.id).count()
        max_files = 50
        if user_file_count >= max_files:
            msg = f"You have reached the maximum limit of {max_files} files. Please delete some files before uploading new ones."
            return jsonify(success=False, error=msg) if is_ajax else (flash(msg, "danger"), redirect(url_for("main.dashboard")))[1]

        # Check storage space
        has_space, available_mb, used_mb = check_storage_space(current_user.id, size)
        if not has_space:
            msg = f"Storage limit exceeded. You have used {used_mb:.1f}MB of 100MB. Available: {available_mb:.1f}MB. Please delete some files or contact support for storage upgrade."
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
