# ACC Portal System

A Flask-based student portal: registration (with valid ID upload), login, and scholarship applications.

## Setup

1. **Create a virtual environment (recommended):**
   ```bash
   python3 -m venv venv
   source venv/bin/activate      # Windows: venv\Scripts\activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the app:**
   ```bash
   python app.py
   ```
   This creates `acc_portal.db` (SQLite) automatically on first run.

4. **Open in browser:**
   ```
   http://127.0.0.1:5000
   ```

## Project Structure
```
acc_portal/
├── app.py                     # Routes, models, and app logic
├── requirements.txt
├── acc_portal.db               # Created automatically (SQLite)
├── uploads/                    # Stores uploaded valid ID files
├── static/css/style.css
└── templates/
    ├── base.html
    ├── index.html
    ├── register.html
    ├── login.html
    ├── dashboard.html
    └── apply_scholarship.html
```

## Features
- **Register**: student number, full name, email, password + valid ID upload (PNG/JPG/PDF, 5MB max)
- **Login/Logout**: session-based, log in with email or student number
- **Dashboard**: shows profile + scholarship application history/status
- **Apply for Scholarship**: type, GWA, reason — tied to the logged-in student

## Security notes
- Passwords hashed with Werkzeug (`generate_password_hash` / `check_password_hash`)
- Uploads validated by extension + size limit, saved with `secure_filename()` + timestamp
- Before deploying to production:
  - Set `SECRET_KEY` from an environment variable, not hardcoded
  - Add CSRF protection (Flask-WTF)
  - Switch `debug=True` off
  - Restrict `/uploads/<filename>` to admin accounts only
  - Consider adding email verification and rate-limiting on login

## Extending it
- Add an **Admin** role/dashboard to approve/reject scholarship applications
- Add email notifications on status change
- Swap SQLite for PostgreSQL/MySQL for production scale
