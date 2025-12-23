
import streamlit as st
import pandas as pd
import os
import bcrypt
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

EMP_FILE = "employees.csv"
KEY_FILE = "secret.key"
PASS_FILE = "admin.pass"
LOG_FILE = "security_log.txt"

ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"

LOCKOUT_THRESHOLD = 3
LOCKOUT_SECONDS = 60

# Utility: logging events

def log_event(event: str):
    """Append an event with timestamp to the security log file."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{now} - {event}\n"
    with open(LOG_FILE, "a") as f:
        f.write(line)

#  Encryption Key Management
def load_or_create_key():
    """Load existing Fernet key from KEY_FILE or create and save a new one."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        log_event("Generated new encryption key and saved to secret.key")
    return key
    
# Admin password management

def load_or_create_admin_password():
    """
    Load hashed admin password from file.
    If file not exists, create it using DEFAULT_ADMIN_PASSWORD (hashed).
    """
    if os.path.exists(PASS_FILE):
        with open(PASS_FILE, "r") as f:
            hashed = f.read().strip()
    else:
        # create initial admin password (hashed) and save
        hashed_bytes = bcrypt.hashpw(DEFAULT_ADMIN_PASSWORD.encode(), bcrypt.gensalt())
        hashed = hashed_bytes.decode()
        with open(PASS_FILE, "w") as f:
            f.write(hashed)
        log_event("Created default admin password file (first-run).")
    return hashed


# Employee data handling

def create_default_employees(cipher: Fernet):
    """Create a default employees CSV with encrypted salaries."""
    sample = [
        {"Employee ID": "E001", "Name": "Ahmed", "Position": "HR", "Salary": 10000, "Status": "Active", "Last Login": "2025-10-15"},
        {"Employee ID": "E002", "Name": "Sara", "Position": "IT", "Salary": 15000, "Status": "Active", "Last Login": "2025-10-10"},
        {"Employee ID": "E003", "Name": "Omar", "Position": "Finance", "Salary": 20000, "Status": "Suspended", "Last Login": "2025-09-30"},
    ]
    rows = []
    for r in sample:
        enc = cipher.encrypt(str(r["Salary"]).encode()).decode()
        rows.append({
            "Employee ID": r["Employee ID"],
            "Name": r["Name"],
            "Position": r["Position"],
            "Encrypted Salary": enc,
            "Status": r["Status"],
            "Last Login": r["Last Login"]
        })
    df = pd.DataFrame(rows)
    df.to_csv(EMP_FILE, index=False)
    log_event("Created default employees.csv with encrypted salaries.")
    return df

def load_employees(cipher: Fernet):
    """Load employees from CSV; if missing, create defaults."""
    if os.path.exists(EMP_FILE):
        df = pd.read_csv(EMP_FILE, dtype=str)
    else:
        df = create_default_employees(cipher)
    return df

def save_employees(df: pd.DataFrame):
    """Save the employees DataFrame to CSV."""
    df.to_csv(EMP_FILE, index=False)
    log_event("Saved employees.csv (updated).")


# Encryption helpers

def encrypt_salary(cipher: Fernet, salary):
    return cipher.encrypt(str(salary).encode()).decode()

def decrypt_salary(cipher: Fernet, encrypted):
    try:
        return cipher.decrypt(encrypted.encode()).decode()
    except Exception:
        return "[decrypt error]"


# Risk calculation (simple rules)

def risk_level(row):
    """
    Very simple risk rules for demo:
    - If Status == Suspended or Terminated => High/Critical
    - If Last Login older than 30 days => High
    - Else Low/Medium based on position
    """
    status = str(row.get("Status", "")).lower()
    if status == "terminated":
        return "Critical"
    if status == "suspended":
        return "High"
    last_login = row.get("Last Login", "")
    try:
        last_dt = datetime.strptime(last_login, "%Y-%m-%d")
        if (datetime.now() - last_dt).days > 30:
            return "High"
    except Exception:
        # Unable to parse date -> medium risk
        pass
    pos = str(row.get("Position", "")).lower()
    if pos in ("it", "finance"):
        return "Medium"
    return "Low"


# Streamlit UI / App start

st.set_page_config(page_title="Employee Lifecycle Security Dashboard", layout="wide")

# Load / create key and admin password
key = load_or_create_key()
cipher = Fernet(key)
stored_admin_hashed = load_or_create_admin_password()

# Initialize session state for attempts/lock
if "attempts" not in st.session_state:
    st.session_state["attempts"] = 0
if "locked_until" not in st.session_state:
    st.session_state["locked_until"] = None
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

# Sidebar: login
st.sidebar.title("🔐 Admin Login")
username_input = st.sidebar.text_input("Username")
password_input = st.sidebar.text_input("Password", type="password")
login_btn = st.sidebar.button("Login")

# Check if he try more than 3 times
locked = False
if st.session_state["locked_until"]:
    if datetime.now() < st.session_state["locked_until"]:
        locked = True
        remaining = (st.session_state["locked_until"] - datetime.now()).seconds
        st.sidebar.error(f"Too many failed attempts. Try again in {remaining}s.")
    else:
        # Lock expired
        st.session_state["locked_until"] = None
        st.session_state["attempts"] = 0
        locked = False
#check if he use the correct pass. if not the number inc.
if login_btn and not locked:
    if username_input == ADMIN_USERNAME and bcrypt.checkpw(password_input.encode(), stored_admin_hashed.encode()):
        st.session_state["authenticated"] = True
        st.session_state["attempts"] = 0
        log_event(f"SUCCESS login by {username_input}")
        st.sidebar.success("Access granted ✅")
    else:
        st.session_state["attempts"] += 1
        log_event(f"FAILED login attempt for username '{username_input}'")
        st.sidebar.error("Access denied 🚫")
        if st.session_state["attempts"] >= LOCKOUT_THRESHOLD:
            st.session_state["locked_until"] = datetime.now() + timedelta(seconds=LOCKOUT_SECONDS)
            st.sidebar.error(f"Account locked for {LOCKOUT_SECONDS} seconds due to repeated failures.")
            log_event(f"Account locked due to {st.session_state['attempts']} failed attempts.")

# Main layout
st.title("🏢 Employee Lifecycle Security Dashboard")
st.write("Secure demo: authentication, encrypted storage, onboarding/offboarding, logging.")

# If not authenticated, show demo explanation and stop
if not st.session_state["authenticated"]:
    st.info("Please log in from the sidebar using the admin credentials to view and manage the dashboard.")
    st.markdown("**Demo admin username:** `admin`  \n**Demo admin password:** `admin123` (first-run) ")
    st.markdown("---")
    st.markdown("This demo protects sensitive employee data by encrypting salaries and storing logs. Login required to view details.")
    # Show recent log tail (for demo transparency)
    if os.path.exists(LOG_FILE):
        st.subheader("Recent Security Log (read-only):")
        try:
            with open(LOG_FILE, "r") as f:
                lines = f.readlines()[-10:]
            st.text("".join(lines))
        except Exception:
            st.text("Unable to read log file.")
    st.stop()

# -------------------------
# Authenticated area starts
# -------------------------
# Load employees
df = load_employees(cipher)

# Compute risk column
df["Risk"] = df.apply(risk_level, axis=1)

# Left column: overview + risk chart
col1, col2 = st.columns([2, 3])

with col1:
    st.subheader("📁 Employees (Encrypted Salaries)")
    # Show table but hide raw Encrypted Salary? we show it to demonstrate encryption.
    st.dataframe(df[["Employee ID", "Name", "Position", "Encrypted Salary", "Status", "Last Login", "Risk"]], height=300)

    # Show risk summary
    st.subheader("🧠 Risk Summary")
    risk_counts = df["Risk"].value_counts()
    st.bar_chart(risk_counts)

with col2:
    st.subheader("🔍 Admin Actions")

    # 1) Decrypt salaries (explicit action)
    if st.button("Decrypt Salaries (show in table)"):
        df_decrypted = df.copy()
        df_decrypted["Decrypted Salary"] = df_decrypted["Encrypted Salary"].apply(lambda x: decrypt_salary(cipher, x))
        st.dataframe(df_decrypted[["Employee ID", "Name", "Position", "Decrypted Salary", "Status", "Risk"]], height=300)
        log_event(f"Admin decrypted all salaries (user: {ADMIN_USERNAME})")

    st.markdown("----")

    # 2) Add new employee (Onboarding)
    st.markdown("### ➕ Onboard New Employee")
    new_id = st.text_input("Employee ID", value=f"E{100 + len(df) + 1}", key="nid")
    new_name = st.text_input("Name", key="nname")
    new_pos = st.text_input("Position", key="npos")
    new_salary = st.text_input("Salary", key="nsalary")
    new_status = st.selectbox("Status", ["Active", "Suspended", "Terminated"], key="nstatus")
    if st.button("Add Employee"):
        if not (new_id and new_name and new_pos and new_salary):
            st.error("Please provide ID, Name, Position, Salary.")
        else:
            try:
                enc_sal = encrypt_salary(cipher, new_salary)
                row = {
                    "Employee ID": new_id,
                    "Name": new_name,
                    "Position": new_pos,
                    "Encrypted Salary": enc_sal,
                    "Status": new_status,
                    "Last Login": datetime.now().strftime("%Y-%m-%d")
                }
                df = df.append(row, ignore_index=True)
                save_employees(df)
                log_event(f"Added employee {new_id} - {new_name} by {ADMIN_USERNAME}")
                st.success(f"Employee {new_name} added securely.")
            except Exception as e:
                st.error(f"Failed to add employee: {e}")

    st.markdown("----")

    # 3) Offboard / Terminate employee
    st.markdown("### 🚪 Offboard / Terminate Access")
    emp_ids = df["Employee ID"].tolist()
    if emp_ids:
        selected = st.selectbox("Select Employee ID", emp_ids, key="off_id")
        if st.button("Terminate Selected Employee"):
            idx = df.index[df["Employee ID"] == selected].tolist()
            if idx:
                df.loc[idx[0], "Status"] = "Terminated"
                save_employees(df)
                log_event(f"Terminated employee {selected} by {ADMIN_USERNAME}")
                st.warning(f"Access for {selected} has been revoked and status set to Terminated.")
            else:
                st.error("Employee not found.")
    else:
        st.info("No employees found.")

st.markdown("---")

# Lower area: Logs & settings
left, right = st.columns(2)

with left:
    st.subheader("📋 Security Log (last 50 lines)")
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()[-50:]
        st.text("".join(lines))
    else:
        st.text("No logs yet.")

with right:
    st.subheader("⚙️ Settings / Maintenance")
    if st.button("Rotate Encryption Key (demo)"):
        # Rotate key: decrypt all salaries with old key, re-encrypt with new key
        # WARNING: In production, rotating keys requires careful backup/plan.
        old_key = key
        old_cipher = cipher

        # load employees and decrypt all
        temp_df = pd.read_csv(EMP_FILE, dtype=str)
        try:
            decrypted_sals = [decrypt_salary(old_cipher, x) for x in temp_df["Encrypted Salary"]]
        except Exception as e:
            st.error("Failed to decrypt with current key. Rotation aborted.")
            st.stop()

        # generate new key and save
        new_key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(new_key)
        new_cipher = Fernet(new_key)

        # re-encrypt and save
        temp_df["Encrypted Salary"] = [new_cipher.encrypt(str(s).encode()).decode() for s in decrypted_sals]
        temp_df.to_csv(EMP_FILE, index=False)
        log_event("Rotation of encryption key performed by admin.")
        st.success("Key rotated and encrypted salaries re-saved.")

    st.markdown("Note: Key rotation in production requires secure key escrow and audits.")

st.markdown("---")
st.info("End of dashboard. Use the actions above to demonstrate onboarding, offboarding, encryption, and logging.")
