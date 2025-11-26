from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
import re
import uuid
import bcrypt
import secrets
import logging
import threading
import subprocess
import shutil
import smtplib
import time
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from markdown2 import markdown

# -------------------- INITIAL SETUP --------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = "f9d8a3c7b2e14f6d9a7c3b5e8f2d1a4c7b6e9f0d3a2b1c8e"

os.environ['TZ'] = 'Asia/Kuala_Lumpur'
time.tzset()

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------- PATH & ENVIRONMENT CONFIG --------------------
NUCLEI_PATH = os.getenv("NUCLEI_PATH") or shutil.which("nuclei")
LOCAL_TMP_DIR = os.path.join(os.getcwd(), "tmp_reports")
os.makedirs(LOCAL_TMP_DIR, exist_ok=True)

app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# -------------------- DATABASE SETUP --------------------
client = MongoClient("mongodb://localhost:27017/")
db = client["sqscan"]
users_col = db["users"]
scanlogs_col = db["scanlogs"]
reports_col = db["reports"]

# -------------------- EMAIL SETUP --------------------
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_EMAIL = "please setup" # Gmail Address
SMTP_PASSWORD = "please setup"  # Gmail App Password

def send_reset_email(to_email, token):
    reset_link = f"http://127.0.0.1:5000/reset_password/{token}"
    msg = MIMEText(f"""
    <p>Click the link below to reset your password (valid for <b>1 hour</b>):</p>
    <p><a href="{reset_link}">{reset_link}</a></p>
    <p>If you did not request this, please ignore this email.</p>
    """, "html")
    msg["Subject"] = "Password Reset Request"
    msg["From"] = SMTP_EMAIL
    msg["To"] = to_email

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.sendmail(SMTP_EMAIL, to_email, msg.as_string())

# -------------------- HELPER FUNCTIONS --------------------
def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def update_nuclei_templates():
    """Update nuclei templates to the latest version."""
    if not NUCLEI_PATH:
        raise FileNotFoundError("Nuclei binary not found in PATH or NUCLEI_PATH.")
    
    logger.info("Updating Nuclei templates...")
    subprocess.run([NUCLEI_PATH, "-update"], check=False)

# -------------------- NUCLEI SCAN HELPERS --------------------
def manual_templates_for(scan_type):
    """
    Return a list of manually included Nuclei template files for a given scan type.
    """
    base_dir = os.path.expanduser("~/nuclei-templates")
    mapping = {
        "time": [os.path.join(base_dir, "http/cves/2019/CVE-2019-6793.yaml")],
        "boolean": [os.path.join(base_dir, "http/cves/2021/CVE-2021-24340.yaml")],
        "full": [
            os.path.join(base_dir, "http/cves/2019/CVE-2019-6793.yaml"),
            os.path.join(base_dir, "http/cves/2021/CVE-2021-24340.yaml"),
        ],
    }
    return mapping.get((scan_type or "full").lower(), [])


def build_template_condition(scan_type):
    """
    Build the -tc (template condition) expression for Nuclei,
    filtering based on tags for different SQLi scan types.
    """
    primary_tag = "sqli"
    tag_groups = {
        "error": ["error", "error-based", "error-based-sqli", "err"],
        "time": ["time", "time-based", "time-based-sqli"],
        "boolean": ["blind", "boolean", "boolean-based"],
        "union": ["union", "union-based", "union-based-sqli"],
    }

    st = (scan_type or "full").lower()
    if st == "full":
        return f'contains(tags, "{primary_tag}")'

    if st in tag_groups:
        variant_expr = " || ".join(f'contains(tags, "{tag}")' for tag in tag_groups[st])
        return f'contains(tags, "{primary_tag}") && ({variant_expr})'

    # Default fallback
    return f'contains(tags, "{primary_tag}")'


def run_nuclei_local(target, scan_folder_name, scan_type="full", timeout=600):
    # Always update templates first
    update_nuclei_templates()
    """
    Run a normal (scan_type/full) nuclei scan using:
      - /home/kali/nuclei-custom/
      - /home/kali/nuclei-templates/
    Returns (exit_code, stdout, stderr, combined_md_text, md_folder_path)
    """
    if not NUCLEI_PATH:
        raise FileNotFoundError("Nuclei binary not found in PATH or NUCLEI_PATH.")

    # normalize target
    if target and not target.startswith(("http://", "https://")):
        target = "http://" + target

    md_folder = os.path.join(LOCAL_TMP_DIR, scan_folder_name)
    os.makedirs(md_folder, exist_ok=True)

    nuclei_custom_dir = os.path.expanduser("/home/kali/nuclei-custom/")
    nuclei_default_dir = os.path.expanduser("/home/kali/nuclei-templates/")

    cmd = [NUCLEI_PATH]

    # include custom and default directories (if they exist)
    if os.path.exists(nuclei_custom_dir):
        cmd += ["-t", nuclei_custom_dir]
    else:
        logger.debug("nuclei custom dir not found: %s", nuclei_custom_dir)

    if os.path.exists(nuclei_default_dir):
        cmd += ["-t", nuclei_default_dir]
    else:
        logger.debug("nuclei default dir not found: %s", nuclei_default_dir)

    # Add manual templates (full/time/boolean etc)
    for t in manual_templates_for(scan_type):
        if os.path.exists(t):
            cmd += ["-t", t]

    # Add template condition, target and output options
    tc_expr = build_template_condition(scan_type)
    cmd += [
        "-tc", tc_expr,
        "-u", target,
        "-v",
        "-me", md_folder,
        "-timeout", "25",
        "--include-rr"
    ]

    logger.info("Running nuclei (full): %r", cmd)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    exit_code = proc.returncode
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    # combine markdown outputs
    md_text = ""
    if os.path.exists(md_folder):
        for root, _, files in os.walk(md_folder):
            for fname in sorted(files):
                if fname.endswith(".md"):
                    try:
                        with open(os.path.join(root, fname), "r", encoding="utf-8", errors="ignore") as fh:
                            md_text += "\n\n" + fh.read()
                    except Exception:
                        logger.exception("failed to read md %s", fname)

    return exit_code, stdout, stderr, md_text, md_folder


# -------------------- BACKGROUND SCAN WORKER (INDEX + CHILD DETAILS, NO DUP HEADER) --------------------
def background_scan_worker(scan_id, user_id, target, scan_type_id, scan_folder_name,
                           scan_mode="scan_type", template_path=None):
    # Always update templates first
    update_nuclei_templates()
    """
    Runs Nuclei scan and processes results:
    - Reads `index.md` for summary counts.
    - Appends full details from child `.md` files into `combined.md` (without extra headers). filenames.
    - Inserts the report into the database and generates a PDF.
    - Sanitizes `index.md` so host links do not expose child filenames to users.
    - Counts vulnerabilities based on `index.md` (ensuring PDF table matches)
    """
    scan_label = "Template Scan" if scan_mode == "template" else (scan_type_id or "Full Scan")
    logger.info(f"Background worker started for scan {scan_id} target={target} type={scan_label}")

    norm_target = target if target and target.startswith(("http://", "https://")) else ("http://" + target if target else target)
    md_folder_path = os.path.join(LOCAL_TMP_DIR, scan_folder_name)
    vulnerabilities, md_index_data, status = [], "", "Pending"
    exit_code = None
    stdout_text = ""
    stderr_text = ""

    def _sanitize_index_table(index_md: str) -> str:
        """
        Replace markdown links in host column like:
           [192.168.1.12](sqli-...-uuid.md)
        -> [192.168.1.12]
        Only touches lines that begin with '|' (table rows).
        """
        out_lines = []
        for line in index_md.splitlines():
            stripped = line.lstrip()
            if not stripped.startswith("|"):
                out_lines.append(line)
                continue

            cols = line.split("|")
            # host column expected at cols[1] (cols[0] maybe empty)
            if len(cols) > 2:
                host_col = cols[1]
                # replace markdown link [text](url) -> [text]
                host_col_clean = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'[\1]', host_col)
                cols[1] = host_col_clean
                out_lines.append("|".join(cols))
            else:
                out_lines.append(line)
        return "\n".join(out_lines)

    try:
        os.makedirs(md_folder_path, exist_ok=True)

        # ---------------- BUILD NUCLEI COMMAND ----------------
        if scan_mode == "template" and template_path:
            if not os.path.exists(template_path):
                raise FileNotFoundError(f"Template not found: {template_path}")
            cmd = [
                NUCLEI_PATH,
                "-t", template_path,
                "-u", norm_target,
                "-me", md_folder_path,
                "-timeout", "25",
                "--include-rr",
                "-v"
            ]
        else:
            custom_folder = os.path.expanduser("~/nuclei-custom/")
            default_folder = os.path.expanduser("~/nuclei-templates/")
            tc_expr = build_template_condition(scan_type_id or "full")
            cmd = [
                NUCLEI_PATH,
                "-t", custom_folder,
                "-t", default_folder,
                "-tc", tc_expr,
                "-u", norm_target,
                "-v",
                "-me", md_folder_path,
                "-timeout", "25",
                "--include-rr"
            ]

        logger.info("Running nuclei: %s", " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        exit_code, stdout_text, stderr_text = proc.returncode, proc.stdout or "", proc.stderr or ""
        logger.debug("Nuclei finished: exit=%s md_folder=%s stdout_len=%d stderr_len=%d",
                     exit_code, md_folder_path, len(stdout_text), len(stderr_text))

        # READ index.md ONLY (summary table) - fallback to combining all if missing
        index_path = os.path.join(md_folder_path, "index.md")
        index_md = ""
        if os.path.exists(index_path):
            try:
                with open(index_path, "r", encoding="utf-8", errors="ignore") as fh:
                    index_md = fh.read()
            except Exception:
                logger.exception("Failed to read index.md at %s", index_path)
                index_md = ""
        else:
            # fallback: if no index.md, combine all .md into index_md
            logger.warning("index.md not found in %s — falling back to concatenating all .md files", md_folder_path)
            parts = []
            for root, _, files in os.walk(md_folder_path):
                for fname in sorted(files):
                    if fname.endswith(".md"):
                        try:
                            with open(os.path.join(root, fname), "r", encoding="utf-8", errors="ignore") as fh:
                                parts.append(fh.read())
                        except Exception:
                            logger.exception("Failed to read md file %s", fname)
            index_md = "\n\n".join(parts)

        # sanitize index
        index_md = _sanitize_index_table(index_md)
        # keep raw index content for DB
        md_index_data = index_md or ""

        # EXTRACT TABLE ROWS from index.md ONLY: | Host | Finding | Severity |
        raw_rows = []
        for line in md_index_data.splitlines():
            line = line.strip()
            if not line.startswith("|"):
                continue
            cols = [c.strip() for c in line.split("|")]
            # require at least 4 columns: | host | finding | severity |
            if len(cols) < 4:
                continue
            host = cols[1]
            template_id = cols[2]
            severity = cols[3].lower()
            if severity in ["critical", "high", "medium", "low", "info", "unknown"]:
                raw_rows.append((host, template_id, severity))

        # FALLBACK: if there are no table rows, try header-style extraction from combined content
        if not raw_rows:
            header_pattern = re.compile(
                r'^\s*#{1,6}\s+.*\((?P<tid>[a-z0-9\-_]+)\)\s+found on\s+(?P<host>[^\s<\)]+)',
                flags=re.I | re.M
            )
            for m in header_pattern.finditer(md_index_data):
                tid = m.group("tid").strip()
                host = m.group("host").strip()
                # try to detect severity in the following text snippet
                post_slice = md_index_data[m.end(): m.end() + 300]
                sev_match = re.search(r'Severity\s*\|?\s*[:\|]?\s*(critical|high|medium|low|info|unknown)', post_slice, flags=re.I)
                severity = sev_match.group(1).lower() if sev_match else "unknown"
                raw_rows.append((host, tid, severity))

        # DEDUPE + AGGREGATE PER TEMPLATE ID (index-driven, matches PDF)
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        per_template = {}
        for host, tid, sev in raw_rows:
            tid_clean = (tid or "").lower().strip()
            host_clean = (host or "").strip()
            sev_clean = (sev or "unknown").lower()
            if not tid_clean:
                continue
            if tid_clean not in per_template:
                per_template[tid_clean] = {"id": tid_clean, "severity": sev_clean, "hosts": [host_clean] if host_clean else []}
            else:
                # keep worst (lowest rank number)
                if rank.get(sev_clean, 99) < rank.get(per_template[tid_clean]["severity"], 99):
                    per_template[tid_clean]["severity"] = sev_clean
                if host_clean and host_clean not in per_template[tid_clean]["hosts"]:
                    per_template[tid_clean]["hosts"].append(host_clean)

        # build vulnerabilities list sorted by severity
        vulnerabilities = sorted(list(per_template.values()), key=lambda x: rank.get(x["severity"], 99))

        # ATTACH FULL DETAILS: read child .md files and attach the content
        if os.path.exists(md_folder_path):
            # Build a mapping filename -> content once to avoid repeated reads
            file_contents = {}
            for fname in sorted(os.listdir(md_folder_path)):
                if not fname.endswith(".md"):
                    continue
                fullp = os.path.join(md_folder_path, fname)
                try:
                    with open(fullp, "r", encoding="utf-8", errors="ignore") as fh:
                        file_contents[fname] = fh.read()
                except Exception:
                    logger.exception("Failed to read md file %s", fullp)
                    file_contents[fname] = ""

            for vul in vulnerabilities:
                tid = vul["id"]
                attached_texts = []
                seen_uuids = set()
                # find files that match tid (startwith or contains). skip index.md
                for fname, content in file_contents.items():
                    if fname.lower() == "index.md":
                        continue
                    fname_l = fname.lower()
                    if fname_l.startswith(tid.lower()) or tid.lower() in fname_l:
                        # avoid duplicates if nuclei produced duplicate child files
                        if fname in seen_uuids:
                            continue
                        seen_uuids.add(fname)
                        if content:
                            attached_texts.append(content)

                if attached_texts:
                    # join with clear separator but keep original child content intact
                    vul["details"] = "\n\n".join(attached_texts)
                else:
                    vul["details"] = "No additional details available."

        # BUILD combined markdown: sanitized index.md (summary) + concatenated child md files
        combined_parts = []
        combined_parts.append(md_index_data or "# Scan results (no index.md available)\n")

        # Append child details in the same order as vulnerabilities to preserve intent
        for vul in vulnerabilities:
            combined_parts.append("\n\n---\n\n")
            combined_parts.append(vul.get("details", "No additional details available."))

        combined_md = "\n\n".join(combined_parts).strip()

        # Write final combined.md
        combined_md_path = os.path.join(md_folder_path, "combined.md")
        with open(combined_md_path, "w", encoding="utf-8", errors="ignore") as fh:
            fh.write(combined_md)

        # Delete all other markdown files (index.md + child md)
        for fname in os.listdir(md_folder_path):
            if fname.endswith(".md") and fname != "combined.md":
                try:
                    os.remove(os.path.join(md_folder_path, fname))
                except Exception:
                    logger.exception("Failed to remove md file: %s", fname)

        # Store combined.md as index content in DB
        md_index_data = combined_md


        status = "Completed" if exit_code == 0 else "Failed"

        # ---------------- STORE REPORT ----------------
        report_doc = {
            "scan_id": scan_id,
            "user_id": user_id,
            "target": target,
            "format": "markdown",
            "markdown_folder": md_folder_path,
            "index_content": md_index_data,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "exit_code": exit_code,
            "status": status,
            "vulnerabilities": vulnerabilities,
            "created_at": datetime.now(),
        }
        insert_res = reports_col.insert_one(report_doc)
        # attach the inserted id into the doc so downstream functions can reference it
        report_doc["_id"] = insert_res.inserted_id

        # generate PDF from the same combined markdown
        generate_pdf_for_report(report_doc)

        # update scanlog with final counts
        scanlogs_col.update_one(
            {"_id": scan_id},
            {
                "$set": {
                    "scan_status": status,
                    "end_time": datetime.now(),
                    "vulnerabilities_detected": len(vulnerabilities)
                }
            }
        )

    except subprocess.TimeoutExpired:
        logger.exception("Nuclei run timeout for scan %s", scan_id)
        scanlogs_col.update_one({"_id": scan_id}, {"$set": {"scan_status": "Timeout", "end_time": datetime.now()}})
    except Exception as e:
        logger.exception("Error in background worker: %s", e)
        scanlogs_col.update_one({"_id": scan_id}, {"$set": {"scan_status": "Failed", "end_time": datetime.now()}})


# -------------------- REPORT GENERATION (OPTIMIZED) --------------------
def generate_pdf_for_report(report):
    """Generate a PDF report from combined.md only."""
    try:
        from weasyprint import HTML
        from markdown2 import markdown
        from flask import render_template
        import os

        markdown_folder = report.get("markdown_folder")
        combined_md_path = os.path.join(markdown_folder, "combined.md")

        if not os.path.exists(combined_md_path):
            logger.error("combined.md missing for report: %s", report.get("_id"))
            return None

        # Read *only* combined.md
        with open(combined_md_path, "r", encoding="utf-8", errors="ignore") as fh:
            combined_md = fh.read()

        # Convert Markdown to HTML
        html_content = markdown(
            combined_md,
            extras=["fenced-code-blocks", "tables"]
        )

        # WeasyPrint needs app context in background
        with app.app_context():
            html_for_pdf = render_template(
                "pdf_template.html",
                html_content=html_content,
                report=report
            )

            pdf_filename = f"scan_report_{str(report.get('_id'))}.pdf"
            pdf_path = os.path.join(markdown_folder, pdf_filename)

            HTML(string=html_for_pdf).write_pdf(pdf_path)

            reports_col.update_one(
                {"_id": ObjectId(report["_id"])},
                {"$set": {"pdf_path": pdf_path, "pdf_generated_at": datetime.now()}}
            )

        logger.info("PDF generated successfully for report %s", report.get("_id"))
        return pdf_path

    except Exception as e:
        logger.exception("PDF generation failed: %s", e)
        return None


# -------------------- AUTH ROUTES --------------------
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name, email, password = request.form.get("name"), request.form.get("email"), request.form.get("password")
        if not all([name, email, password]):
            flash("All fields are required!", "danger")
            return redirect(url_for("register"))
        if users_col.find_one({"email": email}):
            flash("Email already exists!", "danger")
            return redirect(url_for("register"))
        users_col.insert_one({
            "name": name, 
            "email": email, 
            "password_hash": hash_password(password), 
            "profile_picture": None
        })
        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email, password = request.form.get("email"), request.form.get("password")
        user = users_col.find_one({"email": email})
        if user and verify_password(password, user["password_hash"]):
            session["user_id"], session["name"] = str(user["_id"]), user["name"]
            return redirect(url_for("dashboard"))
        flash("Invalid email or password!", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# -------------------- PASSWORD RESET ROUTES --------------------
@app.route("/reset_request", methods=["GET", "POST"])
def reset_request():
    if request.method == "POST":
        email = request.form.get("email")
        user = users_col.find_one({"email": email})
        if user:
            token = secrets.token_urlsafe(32)
            malaysia_tz = timezone(timedelta(hours=8))
            expiry = datetime.now(malaysia_tz) + timedelta(hours=1)
            users_col.update_one(
                {"email": email}, 
                {
                    "$set": {
                        "reset_token": token, 
                        "token_expiry": expiry
                    }
                }
            )
            send_reset_email(email, token)
            flash("Password reset link has been sent to your email.", "info")
        else:
            flash("Email not found! Please check again.", "danger")
        return redirect(url_for("reset_request"))
    return render_template("reset_request.html")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    malaysia_tz = timezone(timedelta(hours=8))
    user = users_col.find_one({
        "reset_token": token,
        "token_expiry": {"$gt": datetime.now(malaysia_tz)}
    })
    if not user:
        flash("Invalid or expired reset link.", "danger")
        return redirect(url_for("login"))
    if request.method == "POST":
        new_password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        if new_password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(request.url)
        hashed_pw = hash_password(new_password)
        users_col.update_one(
            {"_id": ObjectId(user["_id"])},
            {
                "$set": {
                    "password_hash": hashed_pw, 
                    "reset_token": None, 
                    "token_expiry": None
                }
            }
        )
        flash("Password has been reset! Please login.", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)
    
# -------------------- SCAN STATUS API --------------------
@app.route("/api/scans_status")
def scans_status():
    scans = list(scanlogs_col.find({"user_id": session.get("user_id")}, 
                                   {"_id": 1, "scan_status": 1})
                 .sort("start_time", -1)
                 .limit(5))  # last 5 scans

    # return in the format your JS expects
    statuses = [{"id": str(s["_id"]), "status": s.get("scan_status", "Unknown")} for s in scans]

    return jsonify({"statuses": statuses})

# -------------------- MARK SCAN DONE --------------------
@app.route("/api/mark_scan_done")
def mark_scan_done():
    latest_scan = scanlogs_col.find_one(
        {"user_id": session.get("user_id")},
        sort=[("start_time", -1)]
    )
    if latest_scan and latest_scan.get("scan_status") in ["Completed", "Failed", "Timeout"]:
        if session.get("last_notified_scan") != str(latest_scan["_id"]):
            session["scan_done"] = True
            session["last_notified_scan"] = str(latest_scan["_id"])
    return jsonify({"done": session.get("scan_done", False)})

# -------------------- DASHBOARD ROUTE --------------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please login first!", "danger")
        return redirect(url_for("login"))

    total_scans = scanlogs_col.count_documents({"user_id": session["user_id"]})
    completed_scans = scanlogs_col.count_documents({"user_id": session["user_id"], "scan_status": "Completed"})

    vuln_count_cursor = reports_col.aggregate([
        {
            "$lookup": {
                "from": "scanlogs",
                "localField": "scan_id",
                "foreignField": "_id",
                "as": "scan_info"
            }
        },
        {"$unwind": "$scan_info"},
        {"$match": {"scan_info.user_id": session["user_id"], "vulnerabilities": {"$exists": True}}},
        {"$project": {"count": {"$size": "$vulnerabilities"}}},
        {"$group": {"_id": None, "total": {"$sum": "$count"}}}
    ])
    vulnerabilities_detected = next(vuln_count_cursor, {}).get("total", 0)

    recent_scans = list(scanlogs_col.find({"user_id": session["user_id"]}).sort("start_time", -1).limit(5))

    return render_template("dashboard.html", user={"name": session["name"]},
                           total_scans=total_scans,
                           completed_scans=completed_scans,
                           vulnerabilities_detected=vulnerabilities_detected,
                           recent_scans=recent_scans)

# -------------------- SCAN ROUTES --------------------
@app.route("/scan", methods=["GET", "POST"])
def scan():
    if "user_id" not in session:
        flash("Please login first!", "danger")
        return redirect(url_for("login"))

    # show message only after refresh
    if session.pop("scan_done", None):
        flash("Scan completed successfully!", "success")

    user_folder = get_user_folder()
    templates = [f for f in os.listdir(user_folder) if f.endswith(".yaml")] if user_folder else []

    if request.method == "POST":
        target = request.form.get("url")
        scan_mode = request.form.get("scan_mode") or "scan_type"
        scan_type_id = request.form.get("scan_type")  # may be None for template scan
        template_id = request.form.get("template")
        agreement = request.form.get("agreement")

        if not target or not agreement:
            flash("Please provide a target URL and confirm authorization.", "danger")
            return redirect(url_for("scan"))

        template_id = request.form.get("template")

        # If using template scan, show the actual template filename in scan logs
        if scan_mode == "template" and template_id:
            scan_type_id = template_id

        # Resolve template full path if template selected
        template_path = os.path.join(user_folder, secure_filename(template_id)) if template_id else None
        if scan_mode == "template" and template_id and not os.path.exists(template_path):
            flash(f"Selected template not found: {template_id}", "danger")
            return redirect(url_for("scan"))

        # Insert scan log
        scan_doc = {
            "user_id": session["user_id"],
            "target_url": target,
            "scan_type_id": scan_type_id,
            "scan_mode": scan_mode,
            "scan_status": "Running",
            "start_time": datetime.now(),
            "end_time": None,
        }
        scan_id = scanlogs_col.insert_one(scan_doc).inserted_id
        scan_folder_name = f"fullscan_md_{uuid.uuid4().hex[:8]}"

        # Start background scan
        threading.Thread(
            target=background_scan_worker,
            args=(scan_id, session["user_id"], target, scan_type_id, scan_folder_name, scan_mode, template_path),
            daemon=True
        ).start()

        flash("Scan started in background.", "info")
        return redirect(url_for("scan"))

    # Fetch recent scans and reports
    scans = list(scanlogs_col.find({"user_id": session["user_id"]}).sort("start_time", -1).limit(50))
    reports = {str(r["scan_id"]): r for r in reports_col.find({"scan_id": {"$in": [s["_id"] for s in scans]}})}
    for s in scans:
        s["_id_str"], s["report"] = str(s["_id"]), reports.get(str(s["_id"]))

    return render_template("scan.html", scans=scans, templates=templates, user={"name": session["name"]})

# -------------------- DOWNLOAD MARKDOWN REPORT --------------------
@app.route("/report/md/<report_id>")
def download_report(report_id):
    """Serve the Markdown report (.md) for download."""
    try:
        report = reports_col.find_one({"_id": ObjectId(report_id)})
        if not report or not report.get("markdown_folder"):
            flash("Markdown report not found.", "error")
            return redirect(url_for("scan"))

        markdown_folder = report["markdown_folder"]
        md_files = [f for f in os.listdir(markdown_folder) if f.endswith(".md")]

        if not md_files:
            flash("No markdown files available for this report.", "warning")
            return redirect(url_for("scan"))

        # If multiple Markdown files exist, pick the first one (you can modify this)
        md_path = os.path.join(markdown_folder, md_files[0])
        return send_file(
            md_path,
            as_attachment=True,
            download_name=f"scan_report_{report_id}.md",
            mimetype="text/markdown"
        )

    except Exception as e:
        app.logger.error(f"Failed to send markdown report: {e}")
        flash("Unable to download markdown report.", "error")
        return redirect(url_for("scan"))

# -------------------- REPORT DOWNLOAD ROUTE --------------------
@app.route("/report/pdf/<report_id>")
def report_pdf(report_id):
    """Serve the generated PDF report for download."""
    from flask import send_file

    report = reports_col.find_one({"_id": ObjectId(report_id)})
    if not report or not report.get("pdf_path") or not os.path.exists(report["pdf_path"]):
        flash("PDF report not found or not yet generated.", "error")
        return redirect(url_for("scan"))

    return send_file(
        report["pdf_path"],
        as_attachment=True,
        download_name=f"scan_report_{report_id}.pdf",
        mimetype="application/pdf"
    )
    
# -------------------- DELETE SCAN LOG --------------------
@app.route("/delete_scan/<scan_id>", methods=["POST"])
def delete_scan(scan_id):
    if "user_id" not in session:
        flash("Please login first!", "danger")
        return redirect(url_for("login"))

    user_id = session["user_id"]

    # Find the scan log belonging to this user
    scan = scanlogs_col.find_one({"_id": ObjectId(scan_id), "user_id": user_id})
    if not scan:
        flash("Scan not found or unauthorized access.", "danger")
        return redirect(url_for("scan"))

    # Determine scan folder
    scan_folder = scan.get("folder_path")
    if not scan_folder:
        # Auto-detect folder in tmp_reports
        if os.path.exists(LOCAL_TMP_DIR):
            possible_folders = [
                os.path.join(LOCAL_TMP_DIR, f)
                for f in os.listdir(LOCAL_TMP_DIR)
                if f.startswith("fullscan_md_")
            ]
            if possible_folders:
                # Pick the newest folder (likely the correct one)
                scan_folder = sorted(possible_folders, key=os.path.getctime, reverse=True)[0]

    # Delete the scan folder if it exists
    if scan_folder and os.path.exists(scan_folder):
        try:
            shutil.rmtree(scan_folder)
            print(f"Deleted scan folder: {scan_folder}")
        except Exception as e:
            print(f"Error deleting folder {scan_folder}: {e}")
            flash(f"Error deleting scan folder: {e}", "warning")
    else:
        print("No scan folder found to delete")

    # Delete related report if it exists
    if scan.get("report_id"):
        reports_col.delete_one({"_id": ObjectId(scan["report_id"])})

    # Delete the scan log
    scanlogs_col.delete_one({"_id": ObjectId(scan_id)})

    flash("Scan log deleted successfully.", "success")
    return redirect(url_for("scan"))

# -------------------- TEMPLATE MANAGEMENT ROUTE --------------------
@app.route("/template")
def template():
    if "user_id" not in session:
        flash("Please login first!", "danger")
        return redirect(url_for("login"))

    user_folder = get_user_folder()
    os.makedirs(user_folder, exist_ok=True)
    templates = [f for f in os.listdir(user_folder) if f.endswith(".yaml")]

    return render_template("template.html", template_names=templates, user={"name": session["name"]})

@app.route("/template/create", methods=["POST"])
def create_template():
    if "user_id" not in session:
        return jsonify({"success": False, "error": "Please login first."})

    data = request.get_json()
    name = data.get("name", "").strip()
    content = data.get("content", "").strip()

    if not name or not content:
        return jsonify({"success": False, "error": "Name and content required."})

    if not name.endswith(".yaml"):
        name += ".yaml"

    user_folder = get_user_folder()
    os.makedirs(user_folder, exist_ok=True)
    temp_path = os.path.join(user_folder, f"temp_{secure_filename(name)}")

    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(content)

        result = subprocess.run(
            [NUCLEI_PATH, "-validate", "-t", temp_path],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            # Strip ANSI codes
            stderr_clean = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', result.stderr)

            # Extract only YAML unmarshal errors
            match = re.search(r'line \d+: field .* not found', stderr_clean)
            error_msg = match.group(0) if match else "Nuclei validation failed."

            os.remove(temp_path)
            return jsonify({"success": False, "error": error_msg})

        # Validation passed
        final_path = os.path.join(user_folder, secure_filename(name))
        os.rename(temp_path, final_path)
        return jsonify({"success": True, "message": "Template created successfully!"})

    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({"success": False, "error": str(e)})


@app.route("/template/content/<name>", methods=["GET"])
def get_template_content(name):
    user_folder = get_user_folder()
    path = os.path.join(user_folder, secure_filename(name))
    if not os.path.exists(path):
        return jsonify(success=False, error="Template not found.")
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    return jsonify(success=True, content=content)


@app.route("/template/edit/<template_name>", methods=["POST"])
def edit_template(template_name):
    if "user_id" not in session:
        return jsonify({"success": False, "error": "Please login first."})

    data = request.get_json()
    content = data.get("content", "").strip()
    if not content:
        return jsonify({"success": False, "error": "Template content cannot be empty."})

    user_folder = get_user_folder()
    if not os.path.exists(user_folder):
        return jsonify({"success": False, "error": "User folder not found."})

    temp_path = os.path.join(user_folder, f"temp_{secure_filename(template_name)}")

    try:
        # Save temporary file
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(content)

        # Run nuclei validation
        result = subprocess.run(
            [NUCLEI_PATH, "-validate", "-t", temp_path],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            # Strip ANSI escape codes
            stderr_clean = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', result.stderr)

            # Extract only YAML unmarshal errors
            match = re.search(r'line \d+: field .* not found', stderr_clean)
            error_msg = match.group(0) if match else "Nuclei validation failed."

            os.remove(temp_path)
            return jsonify({"success": False, "error": error_msg})

        # Validation passed, overwrite actual template
        final_path = os.path.join(user_folder, secure_filename(template_name))
        with open(final_path, "w", encoding="utf-8") as f:
            f.write(content)

        os.remove(temp_path)
        return jsonify({"success": True, "message": "Template updated successfully!"})

    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({"success": False, "error": str(e)})


@app.route("/template/delete/<name>", methods=["POST"])
def delete_template(name):
    user_folder = get_user_folder()
    path = os.path.join(user_folder, secure_filename(name))
    if not os.path.exists(path):
        return jsonify(success=False, error="Template not found.")

    try:
        os.remove(path)
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))

# -------------------- ACCOUNT ROUTE --------------------
@app.route("/account", methods=["GET", "POST"])
def account():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    user = users_col.find_one({"_id": ObjectId(user_id)})

    # Create a user-specific folder for profile pictures
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], user_id)
    os.makedirs(user_folder, exist_ok=True)

    if request.method == "POST":
        updated = False

        # --- Update Name ---
        name = request.form.get("name")
        if name and name != user.get("name"):
            users_col.update_one({"_id": ObjectId(user_id)}, {"$set": {"name": name}})
            session["name"] = name
            flash("Name updated successfully!", "success")
            updated = True

        # --- Update Email ---
        email = request.form.get("email")
        if email and email != user.get("email"):
            if users_col.find_one({"email": email}):
                flash("Email already in use!", "danger")
            else:
                users_col.update_one({"_id": ObjectId(user_id)}, {"$set": {"email": email}})
                flash("Email updated successfully!", "success")
                updated = True

        # --- Update New Password ---
        new_password = request.form.get("password")
        if new_password:
            hashed_pw = hash_password(new_password)
            users_col.update_one({"_id": ObjectId(user_id)}, {"$set": {"password_hash": hashed_pw}})
            flash("Password updated successfully!", "success")
            updated = True

        # --- Update Profile Picture ---
        if "profile_picture" in request.files:
            file = request.files["profile_picture"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                save_path = os.path.join(user_folder, filename)
                file.save(save_path)
                users_col.update_one(
                    {"_id": ObjectId(user_id)}, 
                    {"$set": {"profile_picture": f"{user_id}/{filename}"}}
                )
                flash("Profile picture updated successfully!", "success")
                updated = True
            elif file.filename:
                flash("Invalid file type!", "danger")

        if not updated:
            flash("No changes made.", "info")

        return redirect(url_for("account"))

    return render_template("account.html", user=user)

# -------------------- INFO PAGE --------------------
@app.route("/info")
def info():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("info.html", user={"name": session.get("name")})

# -------------------- UTILITY --------------------
def get_user_folder():
    if "user_id" not in session:
        return None
    folder = os.path.join(LOCAL_TMP_DIR, "..", "nuclei-user-custom", str(session["user_id"]))
    os.makedirs(folder, exist_ok=True)
    return folder

# -------------------- MAIN --------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

