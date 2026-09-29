"""
ACC Portal System
------------------
A Flask-based student portal that supports:
  1. Student registration (with valid ID file upload) + credential creation
  2. Login / Logout (session-based authentication)
  3. Scholarship application (available only to logged-in students)

Tech stack: Flask, SQLAlchemy (SQLite), Werkzeug (password hashing + safe uploads)

SECURITY NOTES (read before deploying):
  - Passwords are hashed with Werkzeug's generate_password_hash (never stored in plain text).
  - Uploaded files are validated by extension AND size, and renamed with secure_filename()
    plus a timestamp to prevent collisions/overwrites and path traversal attacks.
  - Session cookies are used for login state; SECRET_KEY must be changed before production.
  - This demo does not include CSRF protection or email verification — for production,
    add Flask-WTF (CSRF tokens) and an email confirmation step.
"""

import os
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy

# --------------------------------------------------------------------------
# APP CONFIGURATION
# --------------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-to-a-random-secret-key'  # TODO: set via env var in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///acc_portal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB max upload size

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

# --- Admin login credentials ---
# Hardcoded for simplicity in this demo. For real deployment, move these to
# environment variables and never commit real credentials to source control.
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)


# --------------------------------------------------------------------------
# DATABASE MODELS
# --------------------------------------------------------------------------
class Student(db.Model):
    """Represents a registered student/user of the ACC Portal."""
    id = db.Column(db.Integer, primary_key=True)
    student_number = db.Column(db.String(20), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    valid_id_filename = db.Column(db.String(255), nullable=False)
    date_registered = db.Column(db.DateTime, default=datetime.utcnow)

    # One student can have many scholarship applications
    applications = db.relationship('ScholarshipApplication', backref='student', lazy=True)

    def set_password(self, raw_password):
        """Hash and store the password. Never store plain text passwords."""
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        """Verify a plain-text password against the stored hash."""
        return check_password_hash(self.password_hash, raw_password)


class ScholarshipApplication(db.Model):
    """Represents a scholarship application submitted by a student."""
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    scholarship_type = db.Column(db.String(100), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    gwa = db.Column(db.String(10), nullable=True)
    status = db.Column(db.String(20), default='Pending')  # Pending / Approved / Rejected
    date_applied = db.Column(db.DateTime, default=datetime.utcnow)


# --------------------------------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------------------------------
def allowed_file(filename):
    """Check that the uploaded file has an allowed extension."""
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(view_func):
    """Decorator that redirects to login if the user has no active session."""
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if 'student_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapped_view


def current_student():
    """Fetch the Student row for the currently logged-in session, or None."""
    student_id = session.get('student_id')
    if student_id is None:
        return None
    return Student.query.get(student_id)


def admin_required(view_func):
    """Decorator that redirects to the admin login if there's no active admin session."""
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Please log in as admin to continue.', 'warning')
            return redirect(url_for('admin_login'))
        return view_func(*args, **kwargs)
    return wrapped_view


# --------------------------------------------------------------------------
# ROUTES
# --------------------------------------------------------------------------
@app.route('/')
def index():
    """Landing page."""
    return render_template('index.html', student=current_student())


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Student registration.
    Collects: student number, full name, email, password, and a valid ID file.
    """
    if request.method == 'POST':
        student_number = request.form.get('student_number', '').strip()
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        valid_id_file = request.files.get('valid_id')

        # --- Basic validation ---
        if not all([student_number, full_name, email, password, confirm_password]):
            flash('Please fill out all fields.', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('register'))

        if Student.query.filter_by(student_number=student_number).first():
            flash('That student number is already registered.', 'danger')
            return redirect(url_for('register'))

        if Student.query.filter_by(email=email).first():
            flash('That email is already registered.', 'danger')
            return redirect(url_for('register'))

        if not valid_id_file or valid_id_file.filename == '':
            flash('Please attach a valid ID (jpg, png, or pdf).', 'danger')
            return redirect(url_for('register'))

        if not allowed_file(valid_id_file.filename):
            flash('Invalid file type. Only PNG, JPG, JPEG, and PDF are allowed.', 'danger')
            return redirect(url_for('register'))

        # --- Save the uploaded ID safely ---
        # secure_filename() strips dangerous characters / path traversal attempts.
        # A timestamp prefix guarantees the filename is unique per upload.
        original_name = secure_filename(valid_id_file.filename)
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
        stored_filename = f"{student_number}_{timestamp}_{original_name}"
        valid_id_file.save(os.path.join(app.config['UPLOAD_FOLDER'], stored_filename))

        # --- Create the student record ---
        new_student = Student(
            student_number=student_number,
            full_name=full_name,
            email=email,
            valid_id_filename=stored_filename,
        )
        new_student.set_password(password)

        db.session.add(new_student)
        db.session.commit()

        flash('Registration successful! You may now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Authenticate a student and start a session."""
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip().lower()  # email or student number
        password = request.form.get('password', '')

        student = Student.query.filter(
            (Student.email == identifier) | (Student.student_number == identifier)
        ).first()

        if student and student.check_password(password):
            session['student_id'] = student.id
            flash(f'Welcome back, {student.full_name}!', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid credentials. Please try again.', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Clear the session."""
    session.pop('student_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Student dashboard: shows profile info and their scholarship applications."""
    student = current_student()
    applications = ScholarshipApplication.query.filter_by(student_id=student.id) \
        .order_by(ScholarshipApplication.date_applied.desc()).all()
    return render_template('dashboard.html', student=student, applications=applications)


@app.route('/scholarship/apply', methods=['GET', 'POST'])
@login_required
def apply_scholarship():
    """Submit a scholarship application (requires an active login session)."""
    student = current_student()

    if request.method == 'POST':
        scholarship_type = request.form.get('scholarship_type', '').strip()
        reason = request.form.get('reason', '').strip()
        gwa = request.form.get('gwa', '').strip()

        if not scholarship_type or not reason:
            flash('Please complete the scholarship type and reason fields.', 'danger')
            return redirect(url_for('apply_scholarship'))

        application = ScholarshipApplication(
            student_id=student.id,
            scholarship_type=scholarship_type,
            reason=reason,
            gwa=gwa,
        )
        db.session.add(application)
        db.session.commit()

        flash('Scholarship application submitted successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('apply_scholarship.html', student=student)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """
    Serve an uploaded ID file so an admin can review it.
    Restricted to logged-in students (their own session) or a logged-in admin.
    """
    if not session.get('is_admin') and 'student_id' not in session:
        flash('Please log in to continue.', 'warning')
        return redirect(url_for('login'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# --------------------------------------------------------------------------
# ADMIN ROUTES
# --------------------------------------------------------------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Simple admin login using hardcoded credentials (see ADMIN_USERNAME/PASSWORD above)."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['is_admin'] = True
            flash('Welcome back, admin!', 'success')
            return redirect(url_for('admin_dashboard'))

        flash('Invalid admin credentials.', 'danger')
        return redirect(url_for('admin_login'))

    return render_template('admin_login.html')


@app.route('/admin/logout')
def admin_logout():
    """Clear the admin session."""
    session.pop('is_admin', None)
    flash('Admin logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/admin')
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """
    Admin dashboard: lists every scholarship application (with the applicant's
    info) so the admin can review and approve/reject each one.
    Supports an optional ?status=Pending/Approved/Rejected filter.
    """
    status_filter = request.args.get('status', '').strip()

    query = ScholarshipApplication.query.join(Student)
    if status_filter in ('Pending', 'Approved', 'Rejected'):
        query = query.filter(ScholarshipApplication.status == status_filter)

    applications = query.order_by(ScholarshipApplication.date_applied.desc()).all()

    counts = {
        'total': ScholarshipApplication.query.count(),
        'pending': ScholarshipApplication.query.filter_by(status='Pending').count(),
        'approved': ScholarshipApplication.query.filter_by(status='Approved').count(),
        'rejected': ScholarshipApplication.query.filter_by(status='Rejected').count(),
    }

    return render_template(
        'admin_dashboard.html',
        applications=applications,
        counts=counts,
        status_filter=status_filter,
    )


@app.route('/admin/application/<int:application_id>/update', methods=['POST'])
@admin_required
def admin_update_application(application_id):
    """Approve or reject a specific scholarship application."""
    new_status = request.form.get('status')

    if new_status not in ('Approved', 'Rejected', 'Pending'):
        flash('Invalid status.', 'danger')
        return redirect(url_for('admin_dashboard'))

    application = ScholarshipApplication.query.get_or_404(application_id)
    application.status = new_status
    db.session.commit()

    flash(f'Application #{application.id} marked as {new_status}.', 'success')
    return redirect(request.referrer or url_for('admin_dashboard'))


# --------------------------------------------------------------------------
# ENTRY POINT
# --------------------------------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates acc_portal.db and tables on first run
    app.run(debug=True)
