import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr
import json
import os
import secrets
import hashlib
import hmac
from datetime import datetime, time, timedelta, date
from pathlib import Path
from urllib.parse import quote
import re

import psycopg2
import requests
from psycopg2 import errors
from dotenv import load_dotenv
from flask import (
    Flask, flash, jsonify, redirect, render_template, request, url_for, session
)

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))
app.secret_key = os.getenv("FLASK_SECRET_KEY", "")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY is missing. Add it to your .env file.")

AUDIT_PASSCODE_PEPPER = os.getenv("AUDIT_PASSCODE_PEPPER") or app.secret_key
LOG_DIR = BASE_DIR / "logs"
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

if os.getenv("VERCEL"):
    logging.basicConfig(
        level=logging.INFO, format=LOG_FORMAT,
        handlers=[logging.StreamHandler()], force=True
    )
else:
    LOG_DIR.mkdir(exist_ok=True)
    logging.basicConfig(
        level=logging.INFO, format=LOG_FORMAT,
        handlers=[
            logging.FileHandler(LOG_DIR / "app.log", encoding="utf-8"),
            logging.StreamHandler(),
        ],
        force=True,
    )

CHANGE_TYPES = [
    "Normal CR", "Emergency CR", "Standard CR", "Forward Fix CR", "Bug Fix CR"
]
DEPLOYMENT_TYPES = ["Automation", "Manual"]
VERIFIED_BY_OPTIONS = ["DBA TEAM", "MW TEAM", "DevOps Team"]
STATUSES = [
    "Pending", "Approved", "Rejected", "Scheduled", "In Progress",
    "Successful", "Failed", "Rolled Back", "Cancelled"
]
STATUS_EMAIL_STATUSES = {"Approved", "Cancelled", "Rejected", "Successful", "Failed"}
SLOT_STARTS = [
    "18:30", "19:00", "19:30", "20:00", "20:30",
    "21:00", "21:30", "22:00", "22:30", "23:00"
]
SLOT_CONSTRAINT = "no_overlapping_deployment_slots"


def get_slot_starts(change_type=None):
    """Emergency CRs may use any half-hour start time across the full day."""
    if (change_type or "").strip().casefold() == "emergency cr":
        return [
            (datetime.combine(date.today(), time.min) +
             timedelta(minutes=30 * index)).strftime("%H:%M")
            for index in range(48)
        ]
    return SLOT_STARTS


def get_connection():
    return psycopg2.connect(
        host=os.environ["DB_HOST"],
        port=int(os.getenv("DB_PORT", "5432")),
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        sslmode=os.getenv("DB_SSLMODE", "require"),
        connect_timeout=15,
        application_name="Flask Deployment Tracker",
    )


def validate_cr_number_with_company_api(cr_number):
    """
    Validate a CR against the company API.

    Configuration:
      CR_API_URL=https://company.example/api/cr/{cr_number}
      CR_API_KEY=...
      CR_API_KEY_HEADER=Authorization
      CR_API_KEY_PREFIX=Bearer
      CR_API_RESPONSE_FIELD=exists
      CR_API_TIMEOUT_SECONDS=10

    If CR_API_URL does not contain {cr_number}, cr_number is sent as a
    query parameter. The configured JSON response field must be a boolean,
    for example {"exists": true}, or {"data": {"exists": true}}.
    """
    api_url = (os.getenv("CR_API_URL") or "").strip()
    api_key = (os.getenv("CR_API_KEY") or "").strip()
    header_name = (os.getenv("CR_API_KEY_HEADER") or "Authorization").strip()
    key_prefix = os.getenv("CR_API_KEY_PREFIX", "Bearer").strip()
    response_field = (os.getenv("CR_API_RESPONSE_FIELD") or "exists").strip()
    try:
        timeout = int(os.getenv("CR_API_TIMEOUT_SECONDS", "10"))
    except ValueError as exc:
        raise RuntimeError("CR_API_TIMEOUT_SECONDS must be a number.") from exc

    if not api_url or not api_key:
        raise RuntimeError(
            "Company CR validation API is not configured. "
            "Contact the application administrator."
        )
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", response_field):
        raise RuntimeError("Invalid CR_API_RESPONSE_FIELD configuration.")
    if not 1 <= timeout <= 60:
        raise RuntimeError("CR API timeout must be between 1 and 60 seconds.")
    if not header_name or "\r" in header_name or "\n" in header_name:
        raise RuntimeError("Invalid CR API authentication header configuration.")

    headers = {
        header_name: f"{key_prefix} {api_key}" if key_prefix else api_key,
        "Accept": "application/json",
    }

    if "{cr_number}" in api_url:
        endpoint = api_url.replace("{cr_number}", quote(cr_number, safe=""))
        params = None
    else:
        endpoint = api_url
        params = {"cr_number": cr_number}

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            params=params,
            timeout=timeout,
            allow_redirects=False,
        )

        # Only interpret 404 as an invalid CR if the company's API documents
        # HTTP 404 as "CR not found".
        if response.status_code == 404:
            return False, "CR number was not found. Please check the CR number."
        if response.status_code in (401, 403):
            raise RuntimeError(
                "Company CR API authentication failed. Check the API key "
                "and authentication settings."
            )

        response.raise_for_status()
        try:
            payload = response.json()
        except ValueError as exc:
            raise RuntimeError("Company CR API returned invalid JSON.") from exc

        if not isinstance(payload, dict):
            raise RuntimeError("Company CR API returned an unexpected response format.")

        result = payload
        for key in response_field.split("."):
            if not isinstance(result, dict) or key not in result:
                raise RuntimeError(
                    f"Company CR API response is missing '{response_field}'. "
                    "Check the API documentation and .env settings."
                )
            result = result[key]

        if not isinstance(result, bool):
            raise RuntimeError(
                "Company CR API validation field must be a JSON boolean."
            )
        if result:
            app.logger.info("Company API verified CR %s", cr_number)
            return True, "CR number verified successfully."

        app.logger.warning("Company API rejected CR %s", cr_number)
        return False, (
            "CR number is invalid or does not exist. Please check the CR number."
        )

    except requests.Timeout as exc:
        app.logger.error("Company CR API request timed out.")
        raise RuntimeError(
            "Company CR validation API timed out. Please retry later. "
            "No booking was saved."
        ) from exc
    except requests.RequestException as exc:
        app.logger.error("Company CR API request failed: %s", type(exc).__name__)
        raise RuntimeError(
            "Unable to verify the CR number with the company API. "
            "Please retry later. No booking was saved."
        ) from exc


def normalize_audit_email(value):
    email = (value or "").strip().lower()
    if len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("Enter a valid email address for Modified By.")
    return email


def audit_passcode_digest(passcode):
    return hmac.new(
        AUDIT_PASSCODE_PEPPER.encode("utf-8"),
        ("deployment-tracker-audit-v1:" + passcode).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def get_audit_user_emails():
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT email FROM public.audit_users ORDER BY email")
            return [row[0] for row in cur.fetchall()]
    except Exception:
        app.logger.exception("Could not load audit user registry; run audit_user_registry.sql")
        return []
    finally:
        if conn is not None:
            conn.close()


def verify_audit_user_credentials(email_value, passcode):
    try:
        email = normalize_audit_email(email_value)
    except ValueError as exc:
        return False, str(exc), 400
    if not re.fullmatch(r"\d{4}", str(passcode or "")):
        return False, "Enter the 4-digit passcode for this email address.", 400

    conn = None
    try:
        conn = get_connection()
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                """SELECT passcode_digest, failed_attempts, locked_until
                   FROM public.audit_users WHERE email = %s FOR UPDATE""",
                (email,),
            )
            row = cur.fetchone()
            if row is None:
                conn.rollback()
                return False, "This email is not registered. Select Add Email to register it.", 401

            stored_digest, failed_attempts, locked_until = row
            now = datetime.now()
            if locked_until and locked_until > now:
                remaining = max(1, int((locked_until - now).total_seconds() // 60) + 1)
                conn.commit()
                return False, f"Too many failed attempts. Try again in about {remaining} minute(s).", 429

            if locked_until and locked_until <= now:
                failed_attempts = 0
                cur.execute(
                    "UPDATE public.audit_users SET failed_attempts = 0, locked_until = NULL WHERE email = %s",
                    (email,),
                )

            candidate_digest = audit_passcode_digest(str(passcode))
            if hmac.compare_digest(str(stored_digest).strip(), candidate_digest):
                cur.execute(
                    """UPDATE public.audit_users SET failed_attempts = 0,
                       locked_until = NULL, last_used_at = CURRENT_TIMESTAMP
                       WHERE email = %s""",
                    (email,),
                )
                conn.commit()
                return True, email, 200

            new_failures = int(failed_attempts or 0) + 1
            if new_failures >= 5:
                cur.execute(
                    "UPDATE public.audit_users SET failed_attempts = %s, locked_until = %s WHERE email = %s",
                    (new_failures, now + timedelta(minutes=15), email),
                )
                conn.commit()
                return False, "Five incorrect attempts reached. This email is locked for 15 minutes.", 429

            cur.execute(
                "UPDATE public.audit_users SET failed_attempts = %s WHERE email = %s",
                (new_failures, email),
            )
            conn.commit()
            return False, f"Incorrect passcode. {5 - new_failures} attempt(s) remaining before a 15-minute lock.", 401
    except Exception:
        if conn is not None:
            conn.rollback()
        app.logger.exception("Audit user passcode verification failed")
        return False, "Audit identity storage is unavailable. Run audit_user_registry.sql and retry.", 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/audit-users/register", methods=["POST"])
def register_audit_user():
    payload = request.get_json(silent=True) or {}
    try:
        email = normalize_audit_email(payload.get("email"))
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400

    conn = None
    try:
        conn = get_connection()
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM public.audit_users WHERE email = %s", (email,))
            if cur.fetchone():
                return jsonify({
                    "success": False,
                    "message": "This email is already registered. Select it and enter its passcode.",
                }), 409

            for _ in range(500):
                passcode = f"{secrets.randbelow(10000):04d}"
                digest = audit_passcode_digest(passcode)
                cur.execute(
                    """INSERT INTO public.audit_users (email, passcode_digest)
                       VALUES (%s, %s) ON CONFLICT DO NOTHING RETURNING email""",
                    (email, digest),
                )
                if cur.fetchone():
                    app.logger.info("Audit identity registered: %s", email)
                    return jsonify({
                        "success": True,
                        "email": email,
                        "passcode": passcode,
                        "message": "Email registered. Save this 4-digit passcode now; it will not be shown again.",
                    }), 201
                cur.execute("SELECT 1 FROM public.audit_users WHERE email = %s", (email,))
                if cur.fetchone():
                    return jsonify({
                        "success": False,
                        "message": "This email is already registered. Select it and enter its passcode.",
                    }), 409
            return jsonify({"success": False, "message": "Could not find an unused 4-digit passcode."}), 503
    except Exception:
        app.logger.exception("Audit user registration failed")
        return jsonify({
            "success": False,
            "message": "Could not register the email. Ensure audit_user_registry.sql has been applied.",
        }), 500
    finally:
        if conn is not None:
            conn.close()


def is_manager_user():
    return str(session.get("role", "")).strip().lower() == "manager"


def is_super_manager_user():
    return str(session.get("role", "")).strip().lower().replace(" ", "_") == "super_manager"


def require_super_manager():
    if not is_super_manager_user():
        return jsonify({"success": False, "message": "Super Manager access is required."}), 403
    return None


def get_release_settings(cur=None):
    own_conn = None
    try:
        if cur is None:
            own_conn = get_connection()
            cur = own_conn.cursor()
        cur.execute("SELECT max_cr_per_slot FROM public.release_calendar_config WHERE id = 1")
        row = cur.fetchone()
        capacity = int(row[0]) if row and row[0] else 1
        return max(1, capacity)
    finally:
        if own_conn is not None:
            cur.close()
            own_conn.close()


def get_blocked_date(cur, deployment_date):
    cur.execute(
        "SELECT message FROM public.release_calendar_blocks WHERE blocked_date = %s",
        (deployment_date,),
    )
    row = cur.fetchone()
    return row[0] if row else None


def validate_deployment_date(deployment_date, is_manager=False):
    if is_manager:
        return
    if deployment_date < date.today():
        raise ValueError("Past deployment dates are not allowed. Please choose today or a future date.")
    if deployment_date.weekday() in (5, 6):
        raise ValueError("Deployments cannot be booked on Saturday or Sunday.")


def write_audit_log(level, message, cr_number=None, rfid=None):
    app.logger.log(getattr(logging, level.upper(), logging.INFO), message)
    conn = None
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO public.deployment_tracker_logs
                       (event_time, log_level, message, cr_number, rfid)
                       VALUES (%s, %s, %s, %s, %s)""",
                    (datetime.now(), level.upper(), message[:2000], cr_number, rfid),
                )
    except Exception:
        app.logger.exception("Could not write to deployment_tracker_logs")
    finally:
        if conn is not None:
            conn.close()


def insert_change_history(cur, deployment_id, cr_number, rfid, modified_by, action, changes):
    cur.execute(
        """INSERT INTO public.deployment_change_history
           (deployment_id, cr_number, rfid, modified_by, action, changes)
           VALUES (%s, %s, %s, %s, %s, %s::jsonb)""",
        (
            deployment_id, cr_number, rfid, modified_by, action,
            json.dumps(changes, default=lambda v: v.isoformat() if hasattr(v, "isoformat") else str(v)),
        ),
    )


def audit_value(value):
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    return value


def generate_rfid():
    return f"{secrets.randbelow(100_000_000):08d}"


def get_existing_rfid(cur, cr_number):
    cur.execute(
        """SELECT rfid FROM public.deployment_tracker
           WHERE LOWER(TRIM(cr_number)) = LOWER(TRIM(%s))
             AND rfid IS NOT NULL ORDER BY id LIMIT 1""",
        (cr_number,),
    )
    row = cur.fetchone()
    return row[0] if row else None


def save_deployment(data):
    raw_cr = (data.get("cr_number") or "").strip()
    cr_suffix = re.sub(r"^CR-", "", raw_cr, flags=re.IGNORECASE).strip()
    if not cr_suffix.isdigit():
        raise ValueError("CR Number must contain digits after the CR- prefix.")
    cr_number = f"CR-{cr_suffix}"

    application_name = (data.get("application_name") or "").strip()
    change_requestor = (data.get("change_requestor") or "").strip()
    if not change_requestor:
        raise ValueError("Change Requestor is required.")
    if len(change_requestor) > 150:
        raise ValueError("Change Requestor cannot exceed 150 characters.")
    if not application_name:
        raise ValueError("Application Name is required.")

    # Mandatory external verification before any database booking insert.
    is_valid_cr, validation_message = validate_cr_number_with_company_api(cr_number)
    if not is_valid_cr:
        raise ValueError(validation_message)

    try:
        deployment_date = datetime.strptime(data["deployment_date"], "%Y-%m-%d").date()
        start_time = datetime.strptime(data["slot_start"], "%H:%M").time()
    except (ValueError, KeyError) as exc:
        raise ValueError("Enter a valid deployment date and time slot.") from exc

    validate_deployment_date(deployment_date, is_manager=is_manager_user())
    change_type = (data.get("change_type") or "").strip()
    if change_type not in CHANGE_TYPES:
        raise ValueError("Invalid change type.")
    if start_time.strftime("%H:%M") not in get_slot_starts(change_type):
        if change_type == "Emergency CR":
            raise ValueError("Emergency CR slots must start on a half-hour boundary between 12:00 AM and 11:30 PM.")
        raise ValueError("Choose a 30-minute slot between 6:30 PM and 11:00 PM.")
    if data.get("deployment_type") not in DEPLOYMENT_TYPES:
        raise ValueError("Invalid deployment type.")
    data["status"] = "Pending"

    roll_back = (data.get("roll_back") or "No").strip()
    if roll_back not in ("Yes", "No"):
        raise ValueError("Invalid rollback selection.")
    data["roll_back"] = roll_back

    slot_start = datetime.combine(deployment_date, start_time)
    slot_end = slot_start + timedelta(minutes=30)
    conn = None
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (cr_number.casefold(),))
                rfid = get_existing_rfid(cur, cr_number)
                if not rfid:
                    for _ in range(20):
                        candidate = generate_rfid()
                        cur.execute("SELECT 1 FROM public.deployment_tracker WHERE rfid = %s LIMIT 1", (candidate,))
                        if cur.fetchone() is None:
                            rfid = candidate
                            break
                    if not rfid:
                        raise RuntimeError("Could not generate an available RFID. Please retry.")

                cur.execute(
                    "SELECT pg_advisory_xact_lock(hashtext(%s))",
                    (f"release-slot:{slot_start.isoformat()}",),
                )
                blocked_message = get_blocked_date(cur, deployment_date)
                if blocked_message is not None:
                    raise ValueError(
                        "This deployment date is blocked by the Super Manager. "
                        f"Message: {blocked_message or 'No bookings are allowed on this date.'}"
                    )

                max_cr_per_slot = get_release_settings(cur)
                cur.execute(
                    """SELECT COUNT(*) FROM public.deployment_tracker
                       WHERE slot_start < %s AND slot_end > %s
                         AND LOWER(TRIM(COALESCE(status, '')))
                             NOT IN ('cancelled', 'rejected')""",
                    (slot_end, slot_start),
                )
                occupied_count = int(cur.fetchone()[0] or 0)
                if occupied_count >= max_cr_per_slot:
                    raise ValueError(
                        f"This slot has reached its limit of {max_cr_per_slot} CR request(s). Please choose another slot."
                    )

                cur.execute(
                    """INSERT INTO public.deployment_tracker (
                       cr_number, rfid, deployment_date, slots, slot_start, slot_end,
                       application_name, deployment_type, change_type, released_by,
                       verified_and_deployed_by, change_requestor, release_notes,
                       incident_number, roll_back, status)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       RETURNING id""",
                    (
                        cr_number, rfid, deployment_date,
                        f"{slot_start:%H:%M} - {slot_end:%H:%M}",
                        slot_start, slot_end, application_name,
                        data["deployment_type"], change_type, None, None,
                        change_requestor,
                        (data.get("release_notes") or "").strip() or None,
                        (data.get("incident_number") or "").strip() or None,
                        data["roll_back"], data["status"],
                    ),
                )
                record_id = cur.fetchone()[0]

        write_audit_log(
            "INFO", f"Request submitted successfully. Record ID={record_id}; slot={slot_start}",
            cr_number, rfid,
        )
        return rfid
    except errors.ExclusionViolation as exc:
        raise ValueError("This slot was just booked by another request. Please refresh and choose another green slot.") from exc
    except errors.UniqueViolation as exc:
        constraint = getattr(exc.diag, "constraint_name", None) or ""
        app.logger.exception("Unique constraint violation: %s", constraint)
        raise RuntimeError("A database uniqueness constraint rejected this request. Check your database constraints and server logs.") from exc
    except psycopg2.Error as exc:
        app.logger.exception("Database save failed; SQLSTATE=%s", exc.pgcode)
        raise RuntimeError("Could not save the request to the database. Check the server logs.") from exc
    finally:
        if conn is not None:
            conn.close()


def get_released_by_users():
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                """SELECT DISTINCT TRIM(released_by) FROM public.deployment_tracker
                   WHERE NULLIF(TRIM(released_by), '') IS NOT NULL ORDER BY 1"""
            )
            return [row[0] for row in cur.fetchall()]
    except Exception:
        app.logger.exception("Could not load Released By users")
        return []
    finally:
        if conn is not None:
            conn.close()


def resolve_verified_deployed_by(data):
    choice = (data.get("verified_and_deployed_by") or "").strip()
    if choice == "__others__":
        custom_name = (data.get("verified_and_deployed_by_other") or "").strip()
        if not custom_name:
            raise ValueError("Please enter a name for Verified and Deployed By.")
        if len(custom_name) > 100:
            raise ValueError("Verified and Deployed By name cannot exceed 100 characters.")
        return custom_name
    if choice in VERIFIED_BY_OPTIONS:
        return choice
    raise ValueError("Please select DBA TEAM, MW TEAM, DevOps Team, or Others.")


def form_context(data=None):
    return {
        "data": data or {},
        "change_types": CHANGE_TYPES,
        "deployment_types": DEPLOYMENT_TYPES,
        "statuses": STATUSES,
        "slot_starts": SLOT_STARTS,
        "emergency_slot_starts": get_slot_starts("Emergency CR"),
    }


@app.route("/governance_tracker", methods=["GET"])
def devops_page():
    return render_template(
        "governance_tracker.html",
        deployment_types=DEPLOYMENT_TYPES,
        change_types=CHANGE_TYPES,
        statuses=STATUSES,
        released_by_users=get_released_by_users(),
        verified_by_options=VERIFIED_BY_OPTIONS,
        audit_user_emails=get_audit_user_emails(),
    )


@app.route("/api/deployment-by-cr", methods=["GET"])
def get_deployment_by_cr():
    cr_number = (request.args.get("cr_number") or "").strip()
    cr_number = re.sub(r"^CR-", "", cr_number, flags=re.IGNORECASE).strip()
    if not cr_number.isdigit():
        return jsonify({"success": False, "message": "Enter a valid CR Number, for example CR-12345."}), 400

    normalized_cr = f"CR-{cr_number}"
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                """SELECT id, cr_number, rfid, deployment_date, slot_start, slot_end,
                          slots, application_name, deployment_type, change_type,
                          released_by, verified_and_deployed_by, change_requestor,
                          release_notes, comments, incident_number, roll_back, status
                   FROM public.deployment_tracker
                   WHERE UPPER(REGEXP_REPLACE(TRIM(cr_number), '^CR-', '', 'i')) = %s
                   ORDER BY id DESC""",
                (cr_number.upper(),),
            )
            rows = cur.fetchall()
            columns = [d[0] for d in cur.description]
        if not rows:
            return jsonify({"success": False, "message": f"No deployment found for {normalized_cr}."}), 404
        deployments = []
        for row in rows:
            record = dict(zip(columns, row))
            for key, value in record.items():
                if isinstance(value, (datetime, date, time)):
                    record[key] = value.isoformat()
                elif value is not None and not isinstance(value, (str, int, float, bool)):
                    record[key] = str(value)
            deployments.append(record)
        return jsonify({
            "success": True,
            "message": f"{len(deployments)} deployment request(s) found for {normalized_cr}.",
            "deployments": deployments,
        })
    except Exception:
        app.logger.exception("DevOps CR lookup failed")
        return jsonify({"success": False, "message": "Could not retrieve deployment details. Check the server logs."}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route("/api/deployment-by-id/<int:deployment_id>", methods=["PUT"])
def update_devops_deployment(deployment_id):
    data = request.get_json(silent=True) or {}
    try:
        modified_by = normalize_audit_email(data.get("modified_by"))
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    passcode = str(data.get("modified_by_passcode") or "").strip()
    if not re.fullmatch(r"\d{4}", passcode):
        return jsonify({"success": False, "message": "Enter the 4-digit passcode for the selected email."}), 400

    required_fields = [
        "deployment_date", "slot_start", "application_name", "deployment_type",
        "change_type", "roll_back", "status", "released_by",
        "verified_and_deployed_by", "change_requestor",
    ]
    for field in required_fields:
        if not str(data.get(field) or "").strip():
            return jsonify({"success": False, "message": f"{field.replace('_', ' ').title()} is required."}), 400
    if data["deployment_type"] not in DEPLOYMENT_TYPES:
        return jsonify({"success": False, "message": "Invalid deployment type."}), 400
    if data["change_type"] not in CHANGE_TYPES:
        return jsonify({"success": False, "message": "Invalid change type."}), 400
    if data["status"] not in STATUSES:
        return jsonify({"success": False, "message": "Invalid status."}), 400
    if data["roll_back"] not in ("Yes", "No"):
        return jsonify({"success": False, "message": "Invalid rollback selection."}), 400

    released_by = (data.get("released_by") or "").strip()
    if not released_by or released_by == "__add__":
        return jsonify({"success": False, "message": "Select a Released By user or enter a new name."}), 400
    if len(released_by) > 100:
        return jsonify({"success": False, "message": "Released By name cannot exceed 100 characters."}), 400
    try:
        verified_and_deployed_by = resolve_verified_deployed_by(data)
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400

    change_requestor = (data.get("change_requestor") or "").strip()
    if not change_requestor:
        return jsonify({"success": False, "message": "Change Requestor is required."}), 400
    if len(change_requestor) > 150:
        return jsonify({"success": False, "message": "Change Requestor cannot exceed 150 characters."}), 400

    try:
        deployment_date = datetime.strptime(data["deployment_date"], "%Y-%m-%d").date()
        start_time = datetime.strptime(data["slot_start"], "%H:%M").time()
    except ValueError:
        return jsonify({"success": False, "message": "Invalid deployment date or slot."}), 400
    if not data["application_name"].strip():
        return jsonify({"success": False, "message": "Application Name is required."}), 400

    ok, message, status_code = verify_audit_user_credentials(modified_by, passcode)
    if not ok:
        return jsonify({"success": False, "message": message}), status_code

    slot_start = datetime.combine(deployment_date, start_time)
    slot_end = slot_start + timedelta(minutes=30)
    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.autocommit = False
        cursor = conn.cursor()
        cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"release-slot:{slot_start.isoformat()}",))
        cursor.execute(
            """SELECT id, cr_number, rfid, deployment_date, slot_start, slot_end,
                      application_name, deployment_type, change_type, released_by,
                      verified_and_deployed_by, change_requestor, release_notes,
                      comments, incident_number, roll_back, status
               FROM public.deployment_tracker WHERE id = %s FOR UPDATE""",
            (deployment_id,),
        )
        old_row = cursor.fetchone()
        if old_row is None:
            conn.rollback()
            return jsonify({"success": False, "message": "Deployment record not found."}), 404
        old_record = dict(zip([d[0] for d in cursor.description], old_row))
        blocked_message = get_blocked_date(cursor, deployment_date)
        if blocked_message is not None:
            conn.rollback()
            return jsonify({"success": False, "message": f"This deployment date is blocked by the Super Manager. Message: {blocked_message}"}), 409

        capacity = get_release_settings(cursor)
        cursor.execute(
            """SELECT COUNT(*) FROM public.deployment_tracker
               WHERE id <> %s AND slot_start < %s AND slot_end > %s
                 AND LOWER(TRIM(COALESCE(status, ''))) NOT IN ('cancelled', 'rejected')""",
            (deployment_id, slot_end, slot_start),
        )
        if int(cursor.fetchone()[0] or 0) >= capacity:
            conn.rollback()
            return jsonify({"success": False, "message": f"This slot has reached the Super Manager limit of {capacity} CR request(s)."}), 409

        new_record = {
            "deployment_date": deployment_date,
            "slot_start": slot_start,
            "slot_end": slot_end,
            "application_name": data["application_name"].strip(),
            "deployment_type": data["deployment_type"],
            "change_type": data["change_type"],
            "released_by": released_by,
            "verified_and_deployed_by": verified_and_deployed_by,
            "change_requestor": change_requestor,
            "release_notes": (data.get("release_notes") or "").strip() or None,
            "comments": (data.get("comments") or "").strip() or None,
            "incident_number": (data.get("incident_number") or "").strip() or None,
            "roll_back": data["roll_back"],
            "status": data["status"],
        }
        cursor.execute(
            """UPDATE public.deployment_tracker SET deployment_date=%s, slots=%s,
               slot_start=%s, slot_end=%s, application_name=%s, deployment_type=%s,
               change_type=%s, released_by=%s, verified_and_deployed_by=%s,
               change_requestor=%s, release_notes=%s, comments=%s, incident_number=%s,
               roll_back=%s, status=%s WHERE id=%s""",
            (
                deployment_date, f"{slot_start:%H:%M} - {slot_end:%H:%M}",
                slot_start, slot_end, new_record["application_name"],
                new_record["deployment_type"], new_record["change_type"], released_by,
                verified_and_deployed_by, change_requestor, new_record["release_notes"],
                new_record["comments"], new_record["incident_number"],
                new_record["roll_back"], new_record["status"], deployment_id,
            ),
        )

        old_status = str(old_record.get("status") or "").strip()
        new_status = str(new_record.get("status") or "").strip()
        changes = {
            field: {"old": audit_value(old_record.get(field)), "new": audit_value(value)}
            for field, value in new_record.items()
            if audit_value(old_record.get(field)) != audit_value(value)
        }
        if changes:
            insert_change_history(cursor, deployment_id, old_record.get("cr_number"),
                                  old_record.get("rfid"), modified_by, "Updated", changes)
        conn.commit()
        write_audit_log(
            "INFO",
            f"DevOps updated deployment record ID={deployment_id}; changed_by={modified_by}; fields={','.join(changes) or 'no changes'}",
            old_record.get("cr_number"), old_record.get("rfid"),
        )

        response_message = "Deployment details updated successfully."
        if old_status != new_status and new_status in STATUS_EMAIL_STATUSES:
            snapshot = dict(old_record)
            snapshot.update(new_record)
            snapshot["id"] = deployment_id
            sent, _ = send_status_change_notification(snapshot, old_status or "Not set", new_status)
            response_message += " Status notification email sent." if sent else " Status was saved, but notification email failed; check logs and SMTP settings."
        return jsonify({"success": True, "message": response_message})
    except errors.ExclusionViolation:
        if conn:
            conn.rollback()
        return jsonify({"success": False, "message": "This slot is already occupied. Choose another available slot."}), 409
    except psycopg2.Error:
        if conn:
            conn.rollback()
        app.logger.exception("DevOps deployment update failed")
        return jsonify({"success": False, "message": "Database update failed. Check server logs."}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/pending-deployments", methods=["GET"])
def pending_deployments():
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, cr_number, rfid, deployment_date, slot_start, slot_end,
                      slots, application_name, deployment_type, change_type, released_by,
                      verified_and_deployed_by, change_requestor, release_notes, comments,
                      incident_number, roll_back, status
               FROM public.deployment_tracker
               WHERE LOWER(TRIM(COALESCE(status, 'Pending'))) = 'pending'
               ORDER BY id DESC"""
        )
        columns = [d[0] for d in cursor.description]
        items = []
        for row in cursor.fetchall():
            record = dict(zip(columns, row))
            for key, value in record.items():
                if isinstance(value, (datetime, date, time)):
                    record[key] = value.isoformat()
                elif value is not None and not isinstance(value, (str, int, float, bool)):
                    record[key] = str(value)
            items.append(record)
        return jsonify({"success": True, "requests": items, "count": len(items)})
    except Exception:
        app.logger.exception("Unable to load pending requests")
        return jsonify({"success": False, "message": "Unable to load pending requests."}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/deployments-by-date", methods=["GET"])
def deployments_by_date():
    date_text = (request.args.get("date") or "").strip()
    try:
        selected_date = date.fromisoformat(date_text)
    except ValueError:
        return jsonify({"success": False, "message": "Choose a valid date in YYYY-MM-DD format."}), 400

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, cr_number, rfid, deployment_date, slot_start, slot_end, slots,
                      application_name, deployment_type, change_type, released_by,
                      verified_and_deployed_by, change_requestor, release_notes, comments,
                      incident_number, roll_back, status
               FROM public.deployment_tracker WHERE deployment_date = %s
               ORDER BY slot_start NULLS LAST, id ASC""",
            (selected_date,),
        )
        columns = [d[0] for d in cursor.description]
        deployments = []
        for row in cursor.fetchall():
            record = dict(zip(columns, row))
            for key, value in record.items():
                if isinstance(value, (datetime, date, time)):
                    record[key] = value.isoformat()
                elif value is not None and not isinstance(value, (str, int, float, bool)):
                    record[key] = str(value)
            deployments.append(record)
        return jsonify({"success": True, "date": selected_date.isoformat(),
                        "deployments": deployments, "count": len(deployments)})
    except Exception:
        app.logger.exception("Unable to load deployments for selected date %s", date_text)
        return jsonify({"success": False, "message": "Unable to load the deployment schedule. Check server logs."}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/deployment-approval/<int:deployment_id>", methods=["POST"])
def decide_deployment_request(deployment_id):
    payload = request.get_json(silent=True) or {}
    try:
        modified_by = normalize_audit_email(payload.get("modified_by"))
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    passcode = str(payload.get("modified_by_passcode") or "").strip()
    if not re.fullmatch(r"\d{4}", passcode):
        return jsonify({"success": False, "message": "Enter the 4-digit passcode for the selected email."}), 400

    decision = (payload.get("decision") or "").strip().lower()
    status_map = {"approve": "Approved", "reject": "Rejected"}
    if decision not in status_map:
        return jsonify({"success": False, "message": "Decision must be approve or reject."}), 400
    ok, message, code = verify_audit_user_credentials(modified_by, passcode)
    if not ok:
        return jsonify({"success": False, "message": message}), code

    conn = None
    cursor = None
    new_status = status_map[decision]
    try:
        conn = get_connection()
        conn.autocommit = False
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, cr_number, rfid, deployment_date, slot_start, slot_end,
                      application_name, deployment_type, change_type, released_by,
                      verified_and_deployed_by, change_requestor, release_notes,
                      comments, incident_number, roll_back, status
               FROM public.deployment_tracker WHERE id = %s FOR UPDATE""",
            (deployment_id,),
        )
        old_row = cursor.fetchone()
        if old_row is None:
            conn.rollback()
            return jsonify({"success": False, "message": "Deployment record not found. Refresh the pending list."}), 409
        columns = [d[0] for d in cursor.description]
        snapshot = dict(zip(columns, old_row))
        old_status = str(snapshot.get("status") or "Pending").strip()
        if old_status.casefold() != "pending":
            conn.rollback()
            return jsonify({"success": False, "message": "Request is no longer pending. Refresh the pending list."}), 409
        cursor.execute(
            """UPDATE public.deployment_tracker SET status = %s
               WHERE id = %s AND LOWER(TRIM(COALESCE(status, 'Pending'))) = 'pending'
               RETURNING cr_number, rfid""",
            (new_status, deployment_id),
        )
        updated = cursor.fetchone()
        if updated is None:
            conn.rollback()
            return jsonify({"success": False, "message": "Request not found or it is no longer pending."}), 409
        snapshot["status"] = new_status
        insert_change_history(cursor, deployment_id, updated[0], updated[1], modified_by,
                              decision.title(), {"status": {"old": old_status, "new": new_status}})
        conn.commit()
        write_audit_log("INFO", f"Deployment request {decision}d: ID={deployment_id}, CR={updated[0]}, status={new_status}, changed_by={modified_by}", updated[0], updated[1])
        response_message = f"Request {new_status.lower()} successfully."
        if old_status != new_status and new_status in STATUS_EMAIL_STATUSES:
            sent, _ = send_status_change_notification(snapshot, old_status, new_status)
            response_message += " Status notification email sent." if sent else " Status was saved, but notification email failed; check logs and SMTP settings."
        return jsonify({"success": True, "message": response_message, "status": new_status})
    except Exception:
        if conn:
            conn.rollback()
        app.logger.exception("Approval/rejection failed")
        return jsonify({"success": False, "message": "Could not save the decision."}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/slot-status", methods=["GET"])
def slot_status():
    date_text = (request.args.get("date") or "").strip()
    try:
        selected_date = datetime.strptime(date_text, "%Y-%m-%d").date()
    except ValueError:
        return jsonify(error="Choose a valid deployment date."), 400
    if not is_manager_user():
        if selected_date < date.today():
            return jsonify({"error": "Past deployment dates are not available for booking."}), 400
        if selected_date.weekday() in (5, 6):
            return jsonify({"error": "Deployments cannot be booked on Saturday or Sunday."}), 400

    change_type = (request.args.get("change_type") or "").strip()
    slots = []
    for start_text in get_slot_starts(change_type):
        start_time = datetime.strptime(start_text, "%H:%M").time()
        end_dt = datetime.combine(selected_date, start_time) + timedelta(minutes=30)
        slots.append({"start": start_text, "end": end_dt.strftime("%H:%M"),
                      "state": "available", "status": "Available"})

    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            blocked_message = get_blocked_date(cur, selected_date)
            capacity = get_release_settings(cur)
            cur.execute(
                """SELECT slot_start, slot_end, status FROM public.deployment_tracker
                   WHERE deployment_date = %s AND slot_start IS NOT NULL AND slot_end IS NOT NULL
                     AND LOWER(TRIM(COALESCE(status, ''))) NOT IN ('cancelled', 'rejected')""",
                (selected_date,),
            )
            rows = cur.fetchall()
        for slot in slots:
            start_dt = datetime.combine(selected_date, datetime.strptime(slot["start"], "%H:%M").time())
            end_dt = start_dt + timedelta(minutes=30)
            active = [
                row for row in rows
                if row[0] < end_dt and row[1] > start_dt
                and (row[2] or "").strip().casefold() not in ("cancelled", "rejected")
            ]
            slot["booked_count"] = len(active)
            slot["capacity"] = capacity
            if blocked_message is not None:
                slot["state"] = "blocked"
                slot["status"] = "Blocked for the day"
            elif len(active) >= capacity:
                slot["state"] = "booked"
                slot["status"] = f"Full ({len(active)}/{capacity})"
            elif active:
                slot["state"] = "available"
                slot["status"] = f"{len(active)}/{capacity} booked; {capacity-len(active)} available"
            else:
                slot["state"] = "available"
                slot["status"] = f"Available (0/{capacity})"
        return jsonify({"date": date_text, "change_type": change_type or None,
                        "blocked": blocked_message is not None, "block_message": blocked_message,
                        "max_cr_per_slot": capacity, "slots": slots})
    except psycopg2.Error:
        app.logger.exception("Could not load slot availability")
        return jsonify(error="Unable to load slot availability. Please retry."), 500
    finally:
        if conn:
            conn.close()


@app.route("/lookup-cr", methods=["GET"])
def lookup_cr():
    cr_number = (request.args.get("cr_number") or "").strip()
    if not cr_number:
        return jsonify(exists=False, rfid=None), 200
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                """SELECT rfid FROM public.deployment_tracker
                   WHERE LOWER(TRIM(cr_number)) = LOWER(TRIM(%s))
                     AND rfid IS NOT NULL ORDER BY id LIMIT 1""",
                (cr_number,),
            )
            row = cur.fetchone()
        return jsonify(exists=bool(row), rfid=str(row[0]) if row else None), 200
    except psycopg2.Error:
        app.logger.exception("CR lookup failed")
        return jsonify(error="Database lookup failed. Please retry."), 500
    finally:
        if conn:
            conn.close()


def _smtp_settings():
    host = (os.getenv("MAIL_SERVER") or "").strip()
    username = (os.getenv("MAIL_USERNAME") or "").strip()
    password = os.getenv("MAIL_PASSWORD", "")
    from_email = (os.getenv("MAIL_FROM_EMAIL") or username).strip()
    from_name = (os.getenv("MAIL_FROM_NAME") or "Deployment Tracker").strip()
    if not host or not username or not password or not from_email:
        return None
    return host, username, password, from_email, from_name


def _send_email(message, recipients):
    settings = _smtp_settings()
    if not settings:
        app.logger.warning("Email skipped because SMTP settings are incomplete.")
        return False, "SMTP settings are incomplete."
    host, username, password, _, _ = settings
    try:
        port = int(os.getenv("MAIL_PORT", "587"))
        use_ssl = os.getenv("MAIL_USE_SSL", "false").strip().lower() in ("1", "true", "yes", "on")
        use_tls = os.getenv("MAIL_USE_TLS", "true").strip().lower() in ("1", "true", "yes", "on")
        timeout = int(os.getenv("MAIL_TIMEOUT_SECONDS", "20"))
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=timeout, context=ssl.create_default_context()) as smtp:
                smtp.login(username, password)
                smtp.send_message(message, to_addrs=recipients)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as smtp:
                smtp.ehlo()
                if use_tls:
                    smtp.starttls(context=ssl.create_default_context())
                    smtp.ehlo()
                smtp.login(username, password)
                smtp.send_message(message, to_addrs=recipients)
        return True, None
    except Exception:
        app.logger.exception("Email delivery failed.")
        return False, "Email delivery failed."


def send_deployment_notification(data, rfid):
    recipients = [
        address.strip()
        for address in re.split(r"[,;\n]+", os.getenv("DEPLOYMENT_EMAIL_RECIPIENTS", ""))
        if address.strip()
    ]
    if not recipients:
        app.logger.warning("Deployment saved, but DEPLOYMENT_EMAIL_RECIPIENTS is not configured.")
        return False, "Email recipients are not configured in .env."
    settings = _smtp_settings()
    if not settings:
        app.logger.warning("Deployment saved, but SMTP configuration is incomplete.")
        return False, "SMTP settings are incomplete in .env."
    _, username, _, from_email, from_name = settings

    cr_number = (data.get("cr_number") or "").strip()
    suffix = re.sub(r"^CR-", "", cr_number, flags=re.IGNORECASE).strip()
    cr_number = f"CR-{suffix}" if suffix else cr_number
    requestor = (data.get("change_requestor") or "").strip() or "Unknown user"
    deployment_date = datetime.strptime(data["deployment_date"], "%Y-%m-%d").date()
    start_time = datetime.strptime(data["slot_start"], "%H:%M").time()
    start = datetime.combine(deployment_date, start_time)
    end = start + timedelta(minutes=30)

    def display(value):
        value = (value or "").strip()
        return value if value else "Not provided"

    message = EmailMessage()
    message["Subject"] = f"{requestor} scheduled the deployment - {cr_number}"
    message["From"] = formataddr((from_name, from_email))
    message["To"] = ", ".join(recipients)
    message.set_content("\n".join([
        f"{requestor} scheduled the deployment.", "", "DEPLOYMENT DETAILS",
        "------------------", f"Scheduled By: {requestor}", f"CR Number: {cr_number}",
        f"RFID: {rfid}", f"Deployment Date: {deployment_date:%d-%m-%Y}",
        f"Slot Timing: {start:%I:%M %p} - {end:%I:%M %p}",
        f"Application Name: {display(data.get('application_name'))}",
        f"Deployment Type: {display(data.get('deployment_type'))}",
        f"Change Type: {display(data.get('change_type'))}",
        f"Change Requestor: {requestor}",
        f"Incident Number: {display(data.get('incident_number'))}",
        f"Release Notes: {display(data.get('release_notes'))}",
        "Status: Pending", "", "Automated notification from the Deployment Tracker.",
    ]))
    return _send_email(message, recipients)


def send_status_change_notification(record, old_status, new_status):
    configured = [
        a.strip().lower()
        for a in re.split(r"[,;\n]+", os.getenv("DEPLOYMENT_EMAIL_RECIPIENTS", ""))
        if a.strip()
    ]
    recipients = sorted(set(configured + [e.lower() for e in get_audit_user_emails() if e]))
    if not recipients:
        return False, "No email recipients are configured."
    settings = _smtp_settings()
    if not settings:
        return False, "SMTP settings are incomplete."
    _, _, _, from_email, from_name = settings

    def display(value):
        if value is None:
            return "Not provided"
        if isinstance(value, (datetime, date, time)):
            return value.isoformat()
        return str(value).strip() or "Not provided"

    dep_date = record.get("deployment_date")
    try:
        if isinstance(dep_date, (datetime, date)):
            date_text = dep_date.strftime("%d-%m-%Y")
        else:
            date_text = date.fromisoformat(str(dep_date)[:10]).strftime("%d-%m-%Y")
    except (TypeError, ValueError):
        date_text = display(dep_date)

    def clock(value):
        if isinstance(value, datetime):
            value = value.time()
        if isinstance(value, time):
            return value.strftime("%I:%M %p")
        if value is not None:
            try:
                return datetime.fromisoformat(str(value)).strftime("%I:%M %p")
            except ValueError:
                try:
                    return time.fromisoformat(str(value)).strftime("%I:%M %p")
                except ValueError:
                    return str(value)
        return "Not provided"

    changed_at = datetime.now().astimezone().strftime("%d-%m-%Y %I:%M:%S %p %Z")
    message = EmailMessage()
    message["Subject"] = f"Deployment Status Update: {display(record.get('cr_number'))} - {new_status}"
    message["From"] = formataddr((from_name, from_email))
    message["To"] = "Undisclosed recipients:;"
    message.set_content("\n".join([
        f"Status changed from {old_status} to {new_status}.",
        f"Status change timestamp: {changed_at}", "", "DEPLOYMENT DETAILS",
        "------------------", f"CR Number: {display(record.get('cr_number'))}",
        f"RFID: {display(record.get('rfid'))}", f"Deployment Date: {date_text}",
        f"Slot Timing: {clock(record.get('slot_start'))} - {clock(record.get('slot_end'))}",
        f"Application Name: {display(record.get('application_name'))}",
        f"Deployment Type: {display(record.get('deployment_type'))}",
        f"Change Type: {display(record.get('change_type'))}",
        f"Released By: {display(record.get('released_by'))}",
        f"Verified and Deployed By: {display(record.get('verified_and_deployed_by'))}",
        f"Change Requestor: {display(record.get('change_requestor'))}",
        f"Incident Number: {display(record.get('incident_number'))}",
        f"Roll Back: {display(record.get('roll_back'))}", f"Status: {new_status}",
        f"Release Notes: {display(record.get('release_notes'))}",
        f"Comments: {display(record.get('comments'))}", "",
        "Automated notification from the Deployment Tracker.",
    ]))
    return _send_email(message, recipients)


@app.route("/", methods=["GET", "POST"])
def Release_Calender():
    if request.method == "GET":
        return render_template("Release_Calender.html", **form_context())
    data = request.form.to_dict()
    required = [
        "cr_number", "deployment_date", "slot_start", "application_name",
        "deployment_type", "change_type", "change_requestor",
    ]
    for field in required:
        if not (data.get(field) or "").strip():
            flash(f"{field.replace('_', ' ').title()} is required.", "error")
            return render_template("Release_Calender.html", **form_context(data)), 400
    try:
        rfid = save_deployment(data)
        email_sent, email_message = send_deployment_notification(data, rfid)
        cr_number = (data.get("cr_number") or "").strip()
        flash(f"Request submitted successfully! CR Number: {cr_number} | RFID: {rfid}", "success")
        if email_sent:
            flash("Email notification sent.", "success")
        else:
            flash(email_message or "Email notification was not sent.", "warning")
        return redirect(url_for("Release_Calender"))
    except ValueError as exc:
        flash(str(exc), "error")
        return render_template("Release_Calender.html", **form_context(data)), 400
    except (RuntimeError, KeyError) as exc:
        app.logger.exception("Request submission failed")
        flash(str(exc), "error")
        return render_template("Release_Calender.html", **form_context(data)), 500


@app.route("/manager", methods=["GET"])
def manager_dashboard():
    conn = None
    cursor = None
    try:
        week_text = (request.args.get("week_start") or "").strip()
        try:
            selected_day = date.fromisoformat(week_text) if week_text else date.today()
        except ValueError:
            selected_day = date.today()
        week_start = selected_day - timedelta(days=selected_day.weekday())
        week_end_exclusive = week_start + timedelta(days=7)
        previous_week_start = week_start - timedelta(days=7)
        next_week_start = week_start + timedelta(days=7)
        day_counts = {week_start + timedelta(days=i): 0 for i in range(7)}

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT COUNT(*) AS total,
               COUNT(*) FILTER (WHERE deployment_date = CURRENT_DATE) AS daily,
               COUNT(*) FILTER (WHERE deployment_date >= date_trunc('week', CURRENT_DATE)::date
                 AND deployment_date < (date_trunc('week', CURRENT_DATE) + INTERVAL '1 week')::date) AS weekly,
               COUNT(*) FILTER (WHERE deployment_date >= date_trunc('month', CURRENT_DATE)::date
                 AND deployment_date < (date_trunc('month', CURRENT_DATE) + INTERVAL '1 month')::date) AS monthly,
               COUNT(*) FILTER (WHERE LOWER(TRIM(COALESCE(roll_back, ''))) = 'yes') AS rollbacks
               FROM public.deployment_tracker"""
        )
        row = cursor.fetchone()
        metrics = {"total": row[0] or 0, "daily": row[1] or 0, "weekly": row[2] or 0,
                   "monthly": row[3] or 0, "rollbacks": row[4] or 0}
        cursor.execute(
            """SELECT deployment_date, COUNT(*) FROM public.deployment_tracker
               WHERE deployment_date >= %s AND deployment_date < %s
               GROUP BY deployment_date ORDER BY deployment_date""",
            (week_start, week_end_exclusive),
        )
        for day, count in cursor.fetchall():
            if day in day_counts:
                day_counts[day] = count
        scale = max(4, max(day_counts.values(), default=0))
        activity_chart = [
            {"date": day.isoformat(), "label": day.strftime("%a"), "count": count,
             "height_percent": round(count / scale * 100, 1)}
            for day, count in day_counts.items()
        ]
        ticks = sorted({scale, round(scale * .75), round(scale * .5), round(scale * .25), 0}, reverse=True)
        cursor.execute(
            """SELECT id, cr_number, rfid, deployment_date, slot_start, slot_end,
                      application_name, deployment_type, change_type, released_by,
                      verified_and_deployed_by, change_requestor, incident_number, roll_back, status
               FROM public.deployment_tracker
               ORDER BY deployment_date DESC, slot_start DESC, id DESC"""
        )
        records = [dict(zip([d[0] for d in cursor.description], r)) for r in cursor.fetchall()]
        cursor.execute(
            """SELECT id, deployment_id, cr_number, rfid, modified_at, modified_by, action, changes
               FROM public.deployment_change_history ORDER BY modified_at DESC, id DESC LIMIT 200"""
        )
        history = [dict(zip([d[0] for d in cursor.description], r)) for r in cursor.fetchall()]
        return render_template(
            "manager.html", metrics=metrics, records=records, activity_chart=activity_chart,
            chart_y_ticks=ticks, chart_scale_max=scale, activity_week_start=week_start,
            activity_week_end=week_start + timedelta(days=6),
            previous_week_start=previous_week_start, next_week_start=next_week_start,
            change_history=history,
        )
    except Exception:
        app.logger.exception("Unable to load manager dashboard")
        return "Unable to load manager dashboard. Check the Flask logs and database connection.", 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/super-manager", methods=["GET"])
def super_manager_page():
    denied = require_super_manager()
    if denied:
        return denied
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT max_cr_per_slot FROM public.release_calendar_config WHERE id = 1")
            row = cur.fetchone()
            capacity = int(row[0]) if row else 1
            cur.execute("SELECT blocked_date, message, updated_at FROM public.release_calendar_blocks ORDER BY blocked_date DESC")
            blocks = cur.fetchall()
            cur.execute(
                """SELECT id, cr_number, rfid, deployment_date, slots, application_name, status, change_requestor
                   FROM public.deployment_tracker ORDER BY deployment_date DESC, slot_start DESC, id DESC LIMIT 1000"""
            )
            deployments = cur.fetchall()
            cur.execute("SELECT email FROM public.audit_users ORDER BY email")
            users = [r[0] for r in cur.fetchall()]
        return render_template("super_manager.html", capacity=capacity, blocks=blocks,
                               deployments=deployments, users=users)
    except Exception:
        app.logger.exception("Could not load Super Manager page")
        return "Could not load Super Manager page. Check server logs and run super_manager_setup.sql.", 500
    finally:
        if conn:
            conn.close()


@app.route("/super-manager/settings", methods=["POST"])
def super_manager_update_capacity():
    denied = require_super_manager()
    if denied:
        return denied
    try:
        capacity = int(request.form.get("max_cr_per_slot", ""))
        if capacity < 1 or capacity > 100:
            raise ValueError
    except (TypeError, ValueError):
        flash("CRs per slot must be a whole number from 1 to 100.", "error")
        return redirect(url_for("super_manager_page"))
    conn = None
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO public.release_calendar_config (id, max_cr_per_slot, updated_at)
                       VALUES (1, %s, CURRENT_TIMESTAMP)
                       ON CONFLICT (id) DO UPDATE SET max_cr_per_slot=EXCLUDED.max_cr_per_slot,
                       updated_at=CURRENT_TIMESTAMP""",
                    (capacity,),
                )
        flash(f"Release Calendar updated: up to {capacity} CR request(s) per slot.", "success")
    except Exception:
        app.logger.exception("Could not update slot capacity")
        flash("Could not update slot capacity. Check server logs.", "error")
    finally:
        if conn:
            conn.close()
    return redirect(url_for("super_manager_page"))


@app.route("/super-manager/block-date", methods=["POST"])
def super_manager_block_date():
    denied = require_super_manager()
    if denied:
        return denied
    date_text = (request.form.get("blocked_date") or "").strip()
    message = (request.form.get("message") or "").strip()
    action = (request.form.get("action") or "block").strip().lower()
    try:
        blocked_date = date.fromisoformat(date_text)
        if action == "block" and not message:
            raise ValueError("Enter a message to display to users.")
        if len(message) > 1000:
            raise ValueError("The message cannot exceed 1000 characters.")
    except ValueError as exc:
        flash(str(exc) or "Choose a valid date.", "error")
        return redirect(url_for("super_manager_page"))
    conn = None
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                if action == "unblock":
                    cur.execute("DELETE FROM public.release_calendar_blocks WHERE blocked_date = %s", (blocked_date,))
                    flash(f"{blocked_date} is now open for booking.", "success")
                else:
                    cur.execute(
                        """INSERT INTO public.release_calendar_blocks (blocked_date, message, updated_at)
                           VALUES (%s, %s, CURRENT_TIMESTAMP)
                           ON CONFLICT (blocked_date) DO UPDATE SET message=EXCLUDED.message,
                           updated_at=CURRENT_TIMESTAMP""",
                        (blocked_date, message),
                    )
                    flash(f"{blocked_date} is blocked. New bookings are disabled for that day.", "success")
    except Exception:
        app.logger.exception("Could not change blocked date")
        flash("Could not update blocked date. Check server logs.", "error")
    finally:
        if conn:
            conn.close()
    return redirect(url_for("super_manager_page"))


@app.route("/super-manager/delete-requests", methods=["POST"])
def super_manager_delete_requests():
    denied = require_super_manager()
    if denied:
        return denied
    ids = []
    for item in request.form.getlist("deployment_ids"):
        try:
            value = int(item)
            if value > 0:
                ids.append(value)
        except (TypeError, ValueError):
            pass
    ids = sorted(set(ids))
    if not ids:
        flash("Select at least one deployment request to delete.", "error")
        return redirect(url_for("super_manager_page"))
    conn = None
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, cr_number, rfid FROM public.deployment_tracker WHERE id = ANY(%s)", (ids,))
                rows = cur.fetchall()
                cur.execute("DELETE FROM public.deployment_tracker WHERE id = ANY(%s)", (ids,))
                deleted = cur.rowcount
                for record_id, cr_number, rfid in rows:
                    cur.execute(
                        """INSERT INTO public.deployment_tracker_logs
                           (event_time, log_level, message, cr_number, rfid)
                           VALUES (CURRENT_TIMESTAMP, 'WARNING', %s, %s, %s)""",
                        (f"Super Manager deleted deployment request id={record_id}", cr_number, rfid),
                    )
        flash(f"Deleted {deleted} deployment request(s). Existing change-history rows were not deleted.", "success")
    except Exception:
        app.logger.exception("Bulk deployment deletion failed")
        flash("Could not delete selected requests. Check logs.", "error")
    finally:
        if conn:
            conn.close()
    return redirect(url_for("super_manager_page"))


@app.route("/super-manager/delete-user", methods=["POST"])
def super_manager_delete_user():
    denied = require_super_manager()
    if denied:
        return denied
    email = (request.form.get("email") or "").strip().lower()
    if not email:
        flash("Select a registered user to remove.", "error")
        return redirect(url_for("super_manager_page"))
    conn = None
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM public.audit_users WHERE LOWER(email) = %s", (email,))
                deleted = cur.rowcount
        flash(f"Removed {email} from the audit-user registry." if deleted else "User was not found.",
              "success" if deleted else "error")
    except Exception:
        app.logger.exception("Could not delete audit user")
        flash("Could not remove the user. Check server logs.", "error")
    finally:
        if conn:
            conn.close()
    return redirect(url_for("super_manager_page"))


@app.route("/super-manager/unlock", methods=["GET", "POST"])
def super_manager_unlock():
    if request.method == "POST":
        submitted_key = request.form.get("access_key", "")
        expected_key = os.getenv("SUPER_MANAGER_ACCESS_KEY", "")
        if not expected_key:
            return ("Super Manager is not configured. Add SUPER_MANAGER_ACCESS_KEY to .env and restart Flask.", 500)
        if not hmac.compare_digest(submitted_key, expected_key):
            app.logger.warning("Failed Super Manager access attempt")
            return (
                "<!doctype html><html><head><title>Access denied</title></head>"
                "<body><h2>Invalid access key</h2><p><a href='/super-manager/unlock'>Try again</a></p></body></html>",
                403,
            )
        session.clear()
        session["role"] = "super_manager"
        session.permanent = False
        return redirect(url_for("super_manager_page"))
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Super Manager Access</title>
<style>
body{font-family:Arial,sans-serif;background:#f3f5f9;display:grid;place-items:center;min-height:100vh;margin:0;color:#172033}
form{background:#fff;padding:28px;border-radius:12px;box-shadow:0 8px 30px #0001;width:min(360px,calc(100% - 48px))}
h2{margin-top:0}input,button{box-sizing:border-box;width:100%;padding:12px;margin-top:12px;border-radius:7px;font-size:16px}
input{border:1px solid #ccd2df}button{border:0;background:#174ea6;color:#fff;font-weight:bold;cursor:pointer}
</style></head><body><form method="post"><h2>Super Manager</h2>
<p>Enter your Super Manager access key.</p>
<input type="password" name="access_key" placeholder="Access key" required autofocus>
<button type="submit">Unlock</button></form></body></html>"""


@app.route("/super-manager/logout", methods=["POST"])
def super_manager_logout():
    session.clear()
    return redirect(url_for("super_manager_unlock"))


if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "5000")),
        debug=False,
    )
