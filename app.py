import os
import json
import uuid
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify, abort
from email_validator import validate_email, EmailNotValidError
from utils.mailer import send_email
from dotenv import load_dotenv

APP_DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
USERS_FILE = os.path.join(APP_DATA_DIR, 'users.json')
SESSIONS_FILE = os.path.join(APP_DATA_DIR, 'sessions.json')
EVENTS_FILE = os.path.join(APP_DATA_DIR, 'events.json')
REGISTRATIONS_FILE = os.path.join(APP_DATA_DIR, 'registrations.json')
SUBMISSIONS_FILE = os.path.join(APP_DATA_DIR, 'submissions.json')
RESULTS_FILE = os.path.join(APP_DATA_DIR, 'results.json')
AUDIT_FILE = os.path.join(APP_DATA_DIR, 'audit.json')
SETTINGS_FILE = os.path.join(APP_DATA_DIR, 'settings.json')

os.makedirs(APP_DATA_DIR, exist_ok=True)

for f in [USERS_FILE, SESSIONS_FILE, EVENTS_FILE, REGISTRATIONS_FILE, SUBMISSIONS_FILE, RESULTS_FILE, AUDIT_FILE, SETTINGS_FILE]:
    if not os.path.exists(f):
        with open(f, 'w', encoding='utf-8') as fp:
            json.dump({}, fp)

load_dotenv()

def _quick_load(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def _quick_save(path, data):
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

secret = os.environ.get('FLASK_SECRET_KEY')
if not secret:
    settings = _quick_load(SETTINGS_FILE) or {}
    secret = settings.get('app_secret_key')
    if not secret:
        import base64
        secret = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
        settings['app_secret_key'] = secret
        _quick_save(SETTINGS_FILE, settings)

app = Flask(__name__)
app.secret_key = secret

def load_json(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_json(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


@app.template_filter('md5hex')
def jinja_md5hex(s):
    try:
        return hashlib.md5(str(s).encode()).hexdigest()
    except Exception:
        return ''


def parse_criteria(text: str):
    items = []
    for line in (text or '').splitlines():
        line = line.strip()
        if not line:
            continue
        sep = None
        for candidate in ('|', ':', '='):
            if candidate in line:
                sep = candidate
                break
        if sep:
            name, pts = line.split(sep, 1)
            name = name.strip()
            try:
                points = float(pts.strip())
            except ValueError:
                points = 0.0
        else:
            name = line
            points = 0.0
        items.append({'name': name, 'points': points})
    return items

RATE_LIMITS = {}


def rate_limit(max_calls: int, per_seconds: int):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = f"{request.remote_addr}:{request.endpoint}"
            now = datetime.utcnow().timestamp()
            window = now - per_seconds
            times = [t for t in RATE_LIMITS.get(key, []) if t >= window]
            if len(times) >= max_calls:
                return ("Too many requests. Please try again later.", 429)
            times.append(now)
            RATE_LIMITS[key] = times
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def log_audit(kind: str, payload: dict):
    data = load_json(AUDIT_FILE) or {}
    day = datetime.utcnow().strftime('%Y-%m-%d')
    arr = data.get(day) or []
    arr.append({
        'kind': kind,
        'payload': payload,
        'ts': datetime.utcnow().isoformat()
    })
    data[day] = arr
    save_json(AUDIT_FILE, data)


def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                return redirect(url_for('login'))
            users = load_json(USERS_FILE)
            user = users.get(user_id)
            if not user:
                session.clear()
                return redirect(url_for('login'))
            if role and user.get('role') not in (role if isinstance(role, (list, tuple)) else [role]):
                abort(403)
            request.current_user = user
            request.current_user_id = user_id
            return fn(*args, **kwargs)
        return wrapper
    return decorator


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
@rate_limit(10, 300)
def register():
    if request.method == 'POST':
        data = {k: request.form.get(k, '').strip() for k in [
            'school_name','school_address','school_email',
            'teacher_name','teacher_phone','teacher_email',
            'student_name','student_email','student_phone'
        ]}
        try:
            validate_email(data['school_email'])
            validate_email(data['teacher_email'])
            validate_email(data['student_email'])
        except EmailNotValidError as e:
            flash(str(e), 'error')
            return render_template('register.html', data=data)
        if not data['school_name']:
            flash('School name is required.', 'error')
            return render_template('register.html', data=data)
        for phfld in ('teacher_phone','student_phone'):
            ph = data.get(phfld, '')
            if not ph or not ph.replace('+','').replace('-','').replace(' ','').isdigit() or len(ph) < 7:
                flash('Enter valid phone numbers.', 'error')
                return render_template('register.html', data=data)

        users = load_json(USERS_FILE)
        user_id = str(uuid.uuid4())
        users[user_id] = {
            'role': 'school',
            'created_at': datetime.utcnow().isoformat(),
            'verified': False,
            'profile': data,
            'assigned_events': [],
            'auth': {}
        }
        save_json(USERS_FILE, users)

        token = str(uuid.uuid4())
        sessions = load_json(SESSIONS_FILE)
        sessions[hash_token(token)] = {
            'type': 'verify_email',
            'user_id': user_id,
            'exp': (datetime.utcnow() + timedelta(hours=24)).isoformat()
        }
        save_json(SESSIONS_FILE, sessions)

        verify_link = url_for('verify_email', token=token, _external=True)
        send_email(
            to=data['teacher_email'],
            subject='Verify your email for Symposium Platform',
            body=f"Hello {data['teacher_name']},\n\nPlease verify your email to activate your account: {verify_link}\n\nThe link expires in 24 hours.\n\nThanks"
        )
        log_audit('register', {'user_id': user_id, 'teacher_email': data['teacher_email']})
        flash('Registration received. Please verify email sent to Teacher Incharge.', 'info')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/verify/<token>')
def verify_email(token):
    sessions = load_json(SESSIONS_FILE)
    entry = sessions.get(hash_token(token))
    if not entry or entry.get('type') != 'verify_email':
        flash('Invalid or expired verification link.', 'error')
        return redirect(url_for('index'))
    if datetime.fromisoformat(entry['exp']) < datetime.utcnow():
        flash('Verification link expired.', 'error')
        return redirect(url_for('index'))
    users = load_json(USERS_FILE)
    user = users.get(entry['user_id'])
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('index'))
    user['verified'] = True
    users[entry['user_id']] = user
    save_json(USERS_FILE, users)
    # create password set token
    token2 = str(uuid.uuid4())
    sessions[hash_token(token2)] = {
        'type': 'set_password',
        'user_id': entry['user_id'],
        'exp': (datetime.utcnow() + timedelta(hours=2)).isoformat()
    }
    save_json(SESSIONS_FILE, sessions)
    return redirect(url_for('set_password', token=token2))


@app.route('/set-password/<token>', methods=['GET','POST'])
def set_password(token):
    sessions = load_json(SESSIONS_FILE)
    entry = sessions.get(hash_token(token))
    if not entry or entry.get('type') != 'set_password':
        flash('Invalid or expired link.', 'error')
        return redirect(url_for('index'))
    if datetime.fromisoformat(entry['exp']) < datetime.utcnow():
        flash('Link expired.', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        pwd = request.form.get('password','')
        if len(pwd) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('set_password.html')
        users = load_json(USERS_FILE)
        user = users.get(entry['user_id'])
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('index'))
        # store salted hash
        salt = uuid.uuid4().hex
        user['auth'] = {
            'salt': salt,
            'password_hash': hash_token(salt + pwd)
        }
        users[entry['user_id']] = user
        save_json(USERS_FILE, users)
        del sessions[hash_token(token)]
        save_json(SESSIONS_FILE, sessions)
        flash('Password set. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('set_password.html')


@app.route('/login', methods=['GET','POST'])
@rate_limit(20, 300)
def login():
    if request.method == 'POST':
        email = request.form.get('email','').strip()
        pwd = request.form.get('password','')
        users = load_json(USERS_FILE)
        # find user by teacher email
        found = None
        for uid, u in users.items():
            if u.get('profile',{}).get('teacher_email') == email:
                found = (uid, u)
                break
        if not found:
            flash('Invalid credentials.', 'error')
            return render_template('login.html')
        uid, u = found
        if not u.get('verified'):
            flash('Please verify your email first.', 'error')
            return render_template('login.html')
        auth = u.get('auth',{})
        if not auth:
            flash('Please set your password via verification link.', 'error')
            return render_template('login.html')
        if auth.get('password_hash') != hash_token(auth.get('salt','') + pwd):
            flash('Invalid credentials.', 'error')
            return render_template('login.html')
        session['user_id'] = uid
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required(role=['school','overall','event_head'])
def dashboard():
    user = request.current_user
    events = load_json(EVENTS_FILE)
    regs = load_json(REGISTRATIONS_FILE)
    my_regs = {eid: regs.get(eid, {}).get(request.current_user_id) for eid in events}
    results = load_json(RESULTS_FILE)
    prelims = {}
    for eid in events:
        q = results.get(eid, {}).get('prelims', {}).get(request.current_user_id, {}).get('qualified')
        prelims[eid] = (True if q else False) if q is not None else None
    # Determine if submissions are enabled for this school per event and build shareable token links
    subs = load_json(SUBMISSIONS_FILE)
    submit_ready = {}
    share_link = {}
    for eid in events:
        conf = subs.get(eid, {}).get('schools', {}).get(request.current_user_id)
        ready = bool(conf and conf.get('enabled'))
        submit_ready[eid] = ready
        if conf and conf.get('token'):
            try:
                share_link[eid] = url_for('submit_entry_via_token', token=conf.get('token'), _external=True)
            except Exception:
                share_link[eid] = None
    # Registration disabled map (deadline or per-event lock)
    settings = load_json(SETTINGS_FILE)
    reg_deadline = settings.get('registration_deadline')
    now = datetime.utcnow()
    reg_disabled = {}
    for eid, ev in events.items():
        disabled = bool(ev.get('registration_edit_locked'))
        if not disabled and reg_deadline:
            try:
                disabled = datetime.fromisoformat(reg_deadline) < now
            except Exception:
                pass
        reg_disabled[eid] = disabled
    declared = results.get('_overall_declared_') or False
    popup_link = session.pop('last_share_link', None)
    return render_template('dashboard.html', user=user, events=events, my_regs=my_regs, prelims=prelims, declared=declared, school_id=request.current_user_id, submit_ready=submit_ready, reg_disabled=reg_disabled, share_link=share_link, popup_link=popup_link)


@app.route('/events/<event_id>/register', methods=['GET','POST'])
@login_required(role='school')
def event_register(event_id):
    events = load_json(EVENTS_FILE)
    event = events.get(event_id)
    if not event:
        abort(404)
    # Global registration deadline and per-event edit lock
    settings = load_json(SETTINGS_FILE)
    reg_deadline = settings.get('registration_deadline')
    reg_locked = bool(event.get('registration_edit_locked'))
    can_edit = True
    try:
        if reg_locked or (reg_deadline and datetime.fromisoformat(reg_deadline) < datetime.utcnow()):
            can_edit = False
    except Exception:
        pass
    if request.method == 'POST':
        if not can_edit:
            flash('Editing registrations for this event is disabled.', 'error')
            return redirect(url_for('event_register', event_id=event_id))
    # participants list of dicts
        participants = []
        count = int(request.form.get('count', '0'))
        # Deregistration when count is zero
        if count == 0:
            regs = load_json(REGISTRATIONS_FILE)
            if event_id in regs and request.current_user_id in (regs.get(event_id) or {}):
                del regs[event_id][request.current_user_id]
                if not regs.get(event_id):
                    del regs[event_id]
                save_json(REGISTRATIONS_FILE, regs)
                flash('You have been deregistered from this event.', 'success')
            else:
                flash('No registration found to remove.', 'info')
            return redirect(url_for('dashboard'))
        for i in range(count):
            participants.append({
                'name': request.form.get(f'name_{i}','').strip(),
                'class': request.form.get(f'class_{i}','').strip(),
                'email': request.form.get(f'email_{i}','').strip(),
                'phone': request.form.get(f'phone_{i}','').strip()
            })
        # enforce exact count
        expected = int(event.get('participants', 1))
        if len(participants) != expected:
            flash(f"This event requires exactly {expected} participant(s).", 'error')
            regs = load_json(REGISTRATIONS_FILE)
            existing = regs.get(event_id, {}).get(request.current_user_id, {}).get('participants', [])
            return render_template('event_register.html', event=event, existing=existing, can_edit=can_edit)
        regs = load_json(REGISTRATIONS_FILE)
        regs.setdefault(event_id, {})[request.current_user_id] = {
            'participants': participants,
            'updated_at': datetime.utcnow().isoformat()
        }
        save_json(REGISTRATIONS_FILE, regs)
        # email both teacher and student incharge
        profile = request.current_user.get('profile',{})
        send_email(
            to=profile.get('teacher_email'),
            subject=f'Registration updated for {event.get("name")}',
            body='Your registration has been updated.'
        )
        if profile.get('student_email'):
            send_email(
                to=profile.get('student_email'),
                subject=f'Registration updated for {event.get("name")}',
                body='Your registration has been updated.'
            )
        flash('Registration saved.', 'success')
        return redirect(url_for('dashboard'))
    # GET – show view-only if editing disabled
    regs = load_json(REGISTRATIONS_FILE)
    existing = regs.get(event_id, {}).get(request.current_user_id, {}).get('participants', [])
    if not can_edit:
        flash('Registration editing is disabled for this event. Viewing only.', 'info')
    return render_template('event_register.html', event=event, existing=existing, can_edit=can_edit)


@app.route('/events/<event_id>/submission/setup', methods=['POST'])
@login_required(role=['school'])
def setup_submission(event_id):
    events = load_json(EVENTS_FILE)
    if event_id not in events:
        abort(404)
    if not events[event_id].get('has_submission'):
        flash('Submissions are not enabled for this event.', 'error')
        return redirect(url_for('dashboard'))
    # Must be registered for this event
    regs = load_json(REGISTRATIONS_FILE).get(event_id, {})
    if request.current_user_id not in regs:
        flash('Register for this event before generating a submission link.', 'error')
        return redirect(url_for('dashboard'))
    sub = load_json(SUBMISSIONS_FILE)
    evt = sub.setdefault(event_id, {})
    schools_cfg = evt.setdefault('schools', {})
    # each school has its own config keyed by school_id
    conf = schools_cfg.setdefault(request.current_user_id, {})
    conf['enabled'] = True
    # Once a link exists, only password and deadline may change. Token persists.
    conf['password'] = request.form.get('password') or conf.get('password') or uuid.uuid4().hex[:8]
    # Clamp per-school deadline to not exceed global deadline
    settings = load_json(SETTINGS_FILE)
    global_deadline = settings.get('submission_deadline')
    dl = request.form.get('deadline') or None
    if dl and global_deadline:
        try:
            d1 = datetime.fromisoformat(dl)
            d2 = datetime.fromisoformat(global_deadline)
            if d1 > d2:
                dl = global_deadline
                flash('Per-link deadline was later than overall deadline and has been clamped.', 'info')
        except Exception:
            pass
    conf['deadline'] = dl
    # Use event-level configured max changes (set by admin)
    try:
        conf['max_changes'] = int(events[event_id].get('submission_max_changes', 2))
    except Exception:
        conf['max_changes'] = 2
    # Generate or refresh a unique token for link-based submissions
    if not conf.get('token'):
        conf['token'] = uuid.uuid4().hex
    save_json(SUBMISSIONS_FILE, sub)
    # Save one-time shareable link in session for popup on dashboard
    try:
        session['last_share_link'] = url_for('submit_entry_via_token', token=conf['token'], _external=True)
    except Exception:
        session['last_share_link'] = None
    flash('Submission link generated for your school.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/admin/events/<event_id>/submission/expire/<school_id>', methods=['POST'])
@login_required(role=['overall','event_head'])
def expire_submission(event_id, school_id):
    events = load_json(EVENTS_FILE)
    if event_id not in events:
        abort(404)
    user = request.current_user
    if user['role'] == 'event_head' and event_id not in (user.get('assigned_events') or []):
        abort(403)
    sub = load_json(SUBMISSIONS_FILE)
    conf = sub.get(event_id, {}).get('schools', {}).get(school_id)
    if conf:
        conf['enabled'] = False
        save_json(SUBMISSIONS_FILE, sub)
        flash('Submission link expired.', 'success')
    return redirect(url_for('manage_event', event_id=event_id))


@app.route('/events/<event_id>/submit', methods=['GET','POST'])
@login_required(role=['school'])
@rate_limit(30, 600)
def submit_entry(event_id):
    events = load_json(EVENTS_FILE)
    event = events.get(event_id)
    if not event:
        abort(404)
    if not event.get('has_submission'):
        abort(403)
    # Global submission deadline
    settings = load_json(SETTINGS_FILE)
    global_deadline = settings.get('submission_deadline')
    sub = load_json(SUBMISSIONS_FILE)
    # Dashboard submission for the logged-in school; no password required on submit
    school_id = request.current_user_id
    # Must be registered for this event
    regs = load_json(REGISTRATIONS_FILE).get(event_id, {})
    if school_id not in regs:
        flash('Register for this event before submitting.', 'error')
        return redirect(url_for('dashboard'))
    schools_cfg = sub.get(event_id, {}).get('schools', {})
    conf = schools_cfg.get(school_id) if school_id else None
    # If no conf exists yet (link not generated), create minimal conf for dashboard submissions
    if not conf:
        evt = sub.setdefault(event_id, {})
        schools_cfg = evt.setdefault('schools', {})
        try:
            max_changes = int(event.get('submission_max_changes', 2))
        except Exception:
            max_changes = 2
        conf = schools_cfg.setdefault(school_id, {
            'enabled': False,  # link not enabled until generated
            'password': None,
            'deadline': None,
            'max_changes': max_changes
        })
        save_json(SUBMISSIONS_FILE, sub)
    # deadline check
    if conf.get('deadline'):
        try:
            if datetime.fromisoformat(conf['deadline']) < datetime.utcnow():
                flash('Submission deadline has passed.', 'error')
                return redirect(url_for('index'))
        except Exception:
            pass
    if global_deadline:
        try:
            if datetime.fromisoformat(global_deadline) < datetime.utcnow():
                flash('Submission deadline has passed.', 'error')
                return redirect(url_for('index'))
        except Exception:
            pass
    if request.method == 'POST':
        # Dashboard submissions skip password check and auto-use school name from profile
        users = load_json(USERS_FILE)
        school = users.get(school_id, {}).get('profile',{}).get('school_name','')
        entry_data = request.form.get('entry_data','').strip()
        if not entry_data:
            flash('Entry is required.', 'error')
            return render_template('submit.html', event=event, mode='dashboard')
        evt = sub.setdefault(event_id, {})
        entries = evt.setdefault('entries', {})
        sch_entries = entries.setdefault(school_id, [])
        # limit changes
        max_changes = conf.get('max_changes', 2)
        if len(sch_entries) >= max_changes:
            flash('Submission change limit reached.', 'error')
            return render_template('submit.html', event=event, mode='dashboard')
        sch_entries.append({
            'entry_data': entry_data,
            'submitted_at': datetime.utcnow().isoformat()
        })
        save_json(SUBMISSIONS_FILE, sub)
        log_audit('submission', {'event_id': event_id, 'school_id': school_id})
        flash('Submission received.', 'success')
        return redirect(url_for('index'))
    # GET – dashboard mode
    return render_template('submit.html', event=event, mode='dashboard')


# Public link-based submission using per-school token
@app.route('/s/<token>', methods=['GET','POST'])
@rate_limit(30, 600)
def submit_entry_via_token(token):
    # Find event_id and school_id by token
    sub = load_json(SUBMISSIONS_FILE)
    events = load_json(EVENTS_FILE)
    found = None
    for eid, evt in sub.items():
        confs = evt.get('schools', {})
        for sid, conf in confs.items():
            if conf.get('token') == token:
                found = (eid, sid, conf)
                break
        if found:
            break
    if not found:
        abort(404)
    event_id, school_id, conf = found
    event = events.get(event_id)
    if not conf.get('enabled'):
        abort(403)
    # deadlines
    settings = load_json(SETTINGS_FILE)
    global_deadline = settings.get('submission_deadline')
    try:
        if conf.get('deadline') and datetime.fromisoformat(conf['deadline']) < datetime.utcnow():
            flash('Submission deadline has passed.', 'error')
            return redirect(url_for('index'))
        if global_deadline and datetime.fromisoformat(global_deadline) < datetime.utcnow():
            flash('Submission deadline has passed.', 'error')
            return redirect(url_for('index'))
    except Exception:
        pass
    # Password gate: store unlocked tokens in session
    unlocked = set(session.get('unlocked_tokens', []))
    if request.method == 'POST':
        if 'password' in request.form and 'entry_data' not in request.form:
            if request.form.get('password') != conf.get('password'):
                flash('Invalid submission password.', 'error')
                return render_template('submit.html', event=event, mode='link_password')
            unlocked.add(token)
            session['unlocked_tokens'] = list(unlocked)
            return redirect(url_for('submit_entry_via_token', token=token))
        # submitting entry
        if token not in unlocked:
            flash('Please enter the password first.', 'error')
            return render_template('submit.html', event=event, mode='link_password')
        entry_data = request.form.get('entry_data','').strip()
        if not entry_data:
            flash('Entry is required.', 'error')
            return render_template('submit.html', event=event, mode='link_form')
        # load and append
        sub = load_json(SUBMISSIONS_FILE)
        evt = sub.setdefault(event_id, {})
        entries = evt.setdefault('entries', {})
        sch_entries = entries.setdefault(school_id, [])
        max_changes = conf.get('max_changes', 2)
        if len(sch_entries) >= max_changes:
            flash('Submission change limit reached.', 'error')
            return render_template('submit.html', event=event, mode='link_form')
        sch_entries.append({'entry_data': entry_data, 'submitted_at': datetime.utcnow().isoformat()})
        save_json(SUBMISSIONS_FILE, sub)
        log_audit('submission', {'event_id': event_id, 'school_id': school_id})
        flash('Submission received.', 'success')
        return redirect(url_for('index'))
    # GET views
    if token in unlocked:
        return render_template('submit.html', event=event, mode='link_form')
    return render_template('submit.html', event=event, mode='link_password')


@app.route('/profile', methods=['GET','POST'])
@login_required(role=['school','overall','event_head'])
def profile():
    users = load_json(USERS_FILE)
    user = users.get(request.current_user_id)
    if request.method == 'POST':
        # Editable except school name
        for key in ['school_address','school_email','teacher_name','teacher_phone','teacher_email','student_name','student_email','student_phone']:
            val = request.form.get(key, '').strip()
            if val:
                user['profile'][key] = val
        users[request.current_user_id] = user
        save_json(USERS_FILE, users)
        flash('Profile updated.', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)


# Admin management
@app.route('/admin')
@login_required(role=['overall','event_head'])
def admin_home():
    user = request.current_user
    events = load_json(EVENTS_FILE)
    users = load_json(USERS_FILE)
    settings = load_json(SETTINGS_FILE)
    results = load_json(RESULTS_FILE)
    declared = results.get('_overall_declared_') or False
    return render_template('admin/index.html', user=user, events=events, users=users, settings=settings, declared=declared)

@app.route('/admin/settings', methods=['POST'])
@login_required(role='overall')
def update_settings():
    settings = load_json(SETTINGS_FILE)
    settings['submission_deadline'] = request.form.get('submission_deadline') or None
    settings['registration_deadline'] = request.form.get('registration_deadline') or None
    # Per-event registration edit lock
    events = load_json(EVENTS_FILE)
    for eid in list(events.keys()):
        events[eid]['registration_edit_locked'] = (request.form.get(f'lock_{eid}') == 'on')
    save_json(SETTINGS_FILE, settings)
    save_json(EVENTS_FILE, events)
    if request.form.get('declare_results'):
        results = load_json(RESULTS_FILE)
        results['_overall_declared_'] = True
        save_json(RESULTS_FILE, results)
        flash('Results declared.', 'success')
    else:
        flash('Settings updated.', 'success')
    return redirect(url_for('admin_home'))


@app.route('/admin/events/create', methods=['GET','POST'])
@login_required(role='overall')
def create_event():
    if request.method == 'POST':
        events = load_json(EVENTS_FILE)
        event_id = str(uuid.uuid4())
 
        name = request.form.get('name','').strip()
        if not name:
            flash('Event name is required.', 'error')
            return render_template('admin/create_event.html')
        
        has_prelims = bool(request.form.get('has_prelims'))
        has_submission = bool(request.form.get('has_submission'))
        # submission max changes set by admin
        try:
            submission_max_changes = int(request.form.get('submission_max_changes', '2')) if has_submission else 0
        except Exception:
            submission_max_changes = 2
        
        def collect_criteria(prefix: str):
            names = request.form.getlist(f'{prefix}_name[]')
            maxs = request.form.getlist(f'{prefix}_max[]')
            crits = []
            for n, m in zip(names, maxs):
                n = (n or '').strip()
                if not n:
                    continue
                try:
                    maxv = float(m) if m else 0.0
                except Exception:
                    maxv = 0.0
                crits.append({'name': n, 'max': maxv})
            return crits
        
        criteria_prelims = collect_criteria('crit_pre') if has_prelims else []
        criteria_finals = collect_criteria('crit_fin')
        if not criteria_finals:
            flash('At least one finals criterion is required.', 'error')
            # preserve any position points the user entered
            pos_ranks = request.form.getlist('pos_rank[]')
            pos_vals = request.form.getlist('pos_points[]')
            pos_prefill = {str(r): v for r, v in zip(pos_ranks, pos_vals)}
            return render_template('admin/create_event.html', pos_points=pos_prefill)
            
        if has_prelims and not criteria_prelims:
            flash('Prelims enabled but no prelims criteria provided.', 'error')
            return render_template('admin/create_event.html')
        
        # Collect finals position points (1st, 2nd, 3rd mandatory)
        pos_ranks = request.form.getlist('pos_rank[]')
        pos_vals = request.form.getlist('pos_points[]')
        position_points = {}
        for r, p in zip(pos_ranks, pos_vals):
            r = str((r or '').strip())
            if not r:
                continue
            try:
                position_points[r] = int(float(p or 0))
            except Exception:
                position_points[r] = 0
        if not all(str(i) in position_points for i in (1,2,3)):
            flash('Please provide points for 1st, 2nd and 3rd positions.', 'error')
            return render_template('admin/create_event.html', pos_points=position_points)

        events[event_id] = {
            'name': name,
            'participants': int(request.form.get('participants','1')),
            'has_prelims': has_prelims,
            'has_submission': has_submission,
            'submission_max_changes': submission_max_changes,
            'criteria_prelims': criteria_prelims,
            'criteria_finals': criteria_finals,
            'position_points': position_points or {'1':60,'2':55,'3':40,'4':30}
        }
        save_json(EVENTS_FILE, events)
        flash('Event created.', 'success')
        return redirect(url_for('admin_home'))
    return render_template('admin/create_event.html')


@app.route('/admin/events/<event_id>/edit', methods=['GET','POST'])
@login_required(role='overall')
def edit_event(event_id):
    events = load_json(EVENTS_FILE)
    event = events.get(event_id)
    if not event:
        abort(404)
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        if not name:
            flash('Event name is required.', 'error')
            return render_template('admin/edit_event.html', event=event, event_id=event_id)
            
        event['name'] = name
        event['participants'] = int(request.form.get('participants', event.get('participants',1)))
        event['has_prelims'] = bool(request.form.get('has_prelims'))
        event['has_submission'] = bool(request.form.get('has_submission'))
        # Update submission max changes if submissions are enabled
        if event['has_submission']:
            try:
                event['submission_max_changes'] = int(request.form.get('submission_max_changes', str(event.get('submission_max_changes', 2))))
            except Exception:
                event['submission_max_changes'] = event.get('submission_max_changes', 2)
        else:
            event['submission_max_changes'] = 0
        
        def collect_criteria(prefix: str):
            names = request.form.getlist(f'{prefix}_name[]')
            maxs = request.form.getlist(f'{prefix}_max[]')
            crits = []
            for n, m in zip(names, maxs):
                n = (n or '').strip()
                if not n:
                    continue
                try:
                    maxv = float(m) if m else 0.0
                except Exception:
                    maxv = 0.0
                crits.append({'name': n, 'max': maxv})
            return crits
        
        criteria_finals = collect_criteria('crit_fin')
        if not criteria_finals:
            flash('At least one finals criterion is required.', 'error')
            return render_template('admin/edit_event.html', event=event, event_id=event_id)
        
        if event['has_prelims']:
            criteria_prelims = collect_criteria('crit_pre')
            if not criteria_prelims:
                flash('Prelims enabled but no prelims criteria provided.', 'error')
                return render_template('admin/edit_event.html', event=event, event_id=event_id)
            event['criteria_prelims'] = criteria_prelims
        else:
            event['criteria_prelims'] = []
        
        event['criteria_finals'] = criteria_finals

        # Collect finals position points
        pos_ranks = request.form.getlist('pos_rank[]')
        pos_vals = request.form.getlist('pos_points[]')
        position_points = {}
        for r, p in zip(pos_ranks, pos_vals):
            r = str((r or '').strip())
            if not r:
                continue
            try:
                position_points[r] = int(float(p or 0))
            except Exception:
                position_points[r] = 0
        if not all(str(i) in position_points for i in (1,2,3)):
            flash('Please provide points for 1st, 2nd and 3rd positions.', 'error')
            return render_template('admin/edit_event.html', event=event, event_id=event_id)
        event['position_points'] = position_points
        
        events[event_id] = event
        save_json(EVENTS_FILE, events)
        flash('Event updated.', 'success')
        return redirect(url_for('manage_event', event_id=event_id))
    return render_template('admin/edit_event.html', event=event, event_id=event_id)

@app.route('/admin/events/<event_id>/delete', methods=['POST'])
@login_required(role='overall')
def delete_event(event_id):
    events = load_json(EVENTS_FILE)
    if event_id not in events:
        abort(404)
    
    events.pop(event_id)
    save_json(EVENTS_FILE, events)
    
    regs = load_json(REGISTRATIONS_FILE)
    if event_id in regs:
        regs.pop(event_id)
    save_json(REGISTRATIONS_FILE, regs)

    subs = load_json(SUBMISSIONS_FILE)
    if event_id in subs:
        subs.pop(event_id)
    save_json(SUBMISSIONS_FILE, subs)
    
    results = load_json(RESULTS_FILE)
    if event_id in results:
        results.pop(event_id)
    save_json(RESULTS_FILE, results)
    
    flash('Event deleted successfully.', 'success')
    return redirect(url_for('admin_home'))

@app.route('/admin/events/<event_id>', methods=['GET','POST'])
@login_required(role=['overall','event_head'])
def manage_event(event_id):
    events = load_json(EVENTS_FILE)
    event = events.get(event_id)
    if not event:
        abort(404)
    user = request.current_user
    if user['role'] == 'event_head' and event_id not in (user.get('assigned_events') or []):
        abort(403)
    regs = load_json(REGISTRATIONS_FILE)
    subs = load_json(SUBMISSIONS_FILE)
    users = load_json(USERS_FILE)
    name_map = {uid: (u.get('profile',{}).get('school_name') or uid) for uid, u in users.items()}
    return render_template('admin/manage_event.html', event=event, event_id=event_id, regs=regs.get(event_id,{}), subs=subs.get(event_id,{}),user=user, name_map=name_map)


@app.route('/admin/users', methods=['GET','POST'])
@login_required(role='overall')
def manage_users():
    users = load_json(USERS_FILE)
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'assign_event_head':
            user_id = request.form.get('user_id')
            event_ids = request.form.getlist('event_ids')
            if user_id in users:
                users[user_id]['role'] = 'event_head'
                users[user_id]['assigned_events'] = event_ids
                save_json(USERS_FILE, users)
                flash('Assigned as Event Head for selected events.', 'success')
        elif action == 'delete_user':
            user_id = request.form.get('user_id')
            if user_id in users:
                users.pop(user_id)
                save_json(USERS_FILE, users)
                flash('User deleted.', 'success')
    events = load_json(EVENTS_FILE)
    return render_template('admin/users.html', users=users, events=events)

@app.route('/admin/users/edit/<user_id>', methods=['GET','POST'])
@login_required(role='overall')
def edit_user(user_id):
    users = load_json(USERS_FILE)
    u = users.get(user_id)
    if not u:
        abort(404)
    events = load_json(EVENTS_FILE)
    if request.method == 'POST':
        role = request.form.get('role', u.get('role'))
        u['role'] = role
        if role == 'event_head':
            assigned = request.form.getlist('assigned_events')
            u['assigned_events'] = assigned
        for key in ['school_address','school_email','teacher_name','teacher_phone','teacher_email','student_name','student_email','student_phone']:
            if key in request.form:
                u['profile'][key] = request.form.get(key,'').strip()
        users[user_id] = u
        save_json(USERS_FILE, users)
        flash('User updated.', 'success')
        return redirect(url_for('manage_users'))
    return render_template('admin/edit_user.html', u=u, events=events, user_id=user_id)


@app.route('/admin/events/<event_id>/grade', methods=['GET','POST'])
@login_required(role=['overall','event_head'])
def grade_event(event_id):
    events = load_json(EVENTS_FILE)
    event = events.get(event_id)
    if not event:
        abort(404)
    user = request.current_user
    if user['role'] == 'event_head' and event_id not in (user.get('assigned_events') or []):
        abort(403)
    regs = load_json(REGISTRATIONS_FILE).get(event_id, {})
    submissions = load_json(SUBMISSIONS_FILE).get(event_id, {})
    results = load_json(RESULTS_FILE)
    results.setdefault(event_id, {})
    has_prelims = event.get('has_prelims')

    if request.method == 'POST':
        stage = request.form.get('stage', 'finals')
        if stage not in ('prelims','finals'):
            stage = 'finals'
        results[event_id].setdefault(stage, {})
        
        for school_id, reg in regs.items():
            if school_id not in regs:
                continue
                
            if school_id not in results[event_id][stage]:
                results[event_id][stage][school_id] = {'scores': {}, 'qualified': False}

            if stage == 'prelims':
                qualified = request.form.get(f'qualified_{school_id}') == 'on'
                results[event_id][stage][school_id]['qualified'] = qualified
            
            crits = event['criteria_prelims'] if stage == 'prelims' else event['criteria_finals']
            scores = {}
            for c in crits:
                cname = c['name'] if isinstance(c, dict) else str(c)
                key = f"score_{school_id}_{hashlib.md5(str(cname).encode()).hexdigest()}"
                try:
                    score_val = float(request.form.get(key, '0') or 0)
                    max_score = float(c.get('max', 100) if isinstance(c, dict) else 100)
                    scores[cname] = min(score_val, max_score)
                except ValueError:
                    scores[cname] = 0.0
            results[event_id][stage][school_id]['scores'] = scores
            
            results[event_id][stage][school_id]['graded_at'] = datetime.utcnow().isoformat()
            results[event_id][stage][school_id]['graded_by'] = user.get('profile', {}).get('teacher_name', 'Unknown')
        # Compute and persist ranking for the current stage
        if stage == 'prelims':
            eligible = list(results[event_id].get('prelims', {}).keys())
            crits = event['criteria_prelims']
            stage_key = 'prelims_positions'
        else:  # finals
            eligible = list(results[event_id].get('finals', {}).keys())
            if has_prelims:
                qmap = results[event_id].get('prelims', {})
                eligible = [sid for sid in eligible if qmap.get(sid, {}).get('qualified')]
            crits = event['criteria_finals']
            stage_key = 'finals_positions'

        totals = {}
        for sid in eligible:
            score_map = results[event_id][stage].get(sid, {}).get('scores', {})
            total = 0.0
            for c in crits:
                cname = c['name'] if isinstance(c, dict) else str(c)
                cmax = float((c.get('max') if isinstance(c, dict) else 0) or (c.get('points') if isinstance(c, dict) else 0) or 0)
                val = float(score_map.get(cname, 0.0) or 0)
                if cmax:
                    val = min(val, cmax)
                total += val
            totals[sid] = total

        ranked = sorted(totals.items(), key=lambda x: x[1], reverse=True)
        pos_map = {sid: idx for idx, (sid, _) in enumerate(ranked, start=1)}
        results[event_id][stage_key] = pos_map
        # For backward compatibility, keep 'positions' as finals positions
        if stage == 'finals':
            results[event_id]['positions'] = pos_map
        
        save_json(RESULTS_FILE, results)
        flash('Grades saved successfully.', 'success')
        return redirect(url_for('grade_event', event_id=event_id, stage=stage))

    stage = request.args.get('stage', 'finals')
    if stage not in ('prelims', 'finals'):
        stage = 'finals'
    if stage == 'prelims' and not has_prelims:
        flash('This event does not have prelims.', 'warning')
        stage = 'finals'
    
    stage_results = results.get(event_id, {}).get(stage, {})
    
    def calculate_total(sid, stage_name):
        crits = event['criteria_prelims'] if stage_name == 'prelims' else event['criteria_finals']
        score_map = stage_results.get(sid, {}).get('scores', {})
        total = 0.0
        for c in crits:
            cname = c['name'] if isinstance(c, dict) else str(c)
            cmax = float((c.get('max') if isinstance(c, dict) else 0) or c.get('points', 0) if isinstance(c, dict) else 0)
            val = float(score_map.get(cname, 0.0) or 0)
            if cmax:
                val = min(val, cmax)
            total += val
        return total
    
    stage_criteria = event['criteria_prelims'] if stage == 'prelims' else event['criteria_finals']
    stage_max = sum(float((c.get('max') if isinstance(c, dict) else 0) or c.get('points', 0) if isinstance(c, dict) else 0) for c in stage_criteria)
    
    view_regs = regs
    if stage == 'finals' and has_prelims:
        prelims_results = results.get(event_id, {}).get('prelims', {})
        view_regs = {sid: reg for sid, reg in regs.items() if prelims_results.get(sid, {}).get('qualified')}
    
    totals = {}
    for sid in view_regs.keys():
        totals[sid] = calculate_total(sid, stage)
    
    users = load_json(USERS_FILE)
    name_map = {uid: (u.get('profile',{}).get('school_name') or uid) for uid, u in users.items()}
    
    return render_template('admin/grade_event.html', 
                         event=event, 
                         event_id=event_id,
                         regs=view_regs, 
                         results=stage_results, 
                         stage=stage, 
                         totals=totals, 
                         stage_max=stage_max, 
                         name_map=name_map, 
                         submissions=submissions
                         ,hashlib=hashlib)


@app.route('/results')
def public_results():
    events = load_json(EVENTS_FILE)
    results = load_json(RESULTS_FILE)
    declared = results.get('_overall_declared_') or False
    if not declared:
        return render_template('results.html', declared=False)
    users = load_json(USERS_FILE)
    name_map = {uid: (u.get('profile',{}).get('school_name') or uid) for uid, u in users.items()}
    top3 = {}
    for eid, event in events.items():
        pos = results.get(eid, {}).get('positions', {})
        inv = {}
        for sid, p in pos.items():
            try:
                inv[int(p)] = sid
            except Exception:
                continue
        names = [name_map.get(inv.get(i)) for i in (1,2,3)]
        top3[eid] = names
    points = {}
    for eid, event in events.items():
        pos = results.get(eid, {}).get('positions', {})
        pts_map = event.get('position_points', {'1':60,'2':55,'3':40,'4':30})
        for sid, p in pos.items():
            pts = int(pts_map.get(str(p), 0))
            points[sid] = points.get(sid, 0) + pts
    ranking = sorted(points.items(), key=lambda x: x[1], reverse=True)
    if ranking:
        overall_winner_id, overall_winner_points = ranking[0]
        overall_winner_name = name_map.get(overall_winner_id, overall_winner_id)
    else:
        overall_winner_name, overall_winner_points = None, 0
    return render_template('results.html', declared=True, events=events, top3=top3, overall_winner_name=overall_winner_name, overall_winner_points=overall_winner_points)


@app.route('/admin/overall', methods=['GET','POST'])
@login_required(role='overall')
def overall():
    events = load_json(EVENTS_FILE)
    results = load_json(RESULTS_FILE)
    points = {}
    breakdown = {}
    for eid, event in events.items():
        pos = results.get(eid, {}).get('positions', {})
        pts_map = event.get('position_points', {'1':60,'2':55,'3':40,'4':30})
        for school_id, p in pos.items():
            pts = int(pts_map.get(str(p), 0))
            points[school_id] = points.get(school_id, 0) + pts
            per = breakdown.setdefault(school_id, {})
            per[eid] = per.get(eid, 0) + pts
    ranking = sorted(points.items(), key=lambda x: x[1], reverse=True)
    declared = results.get('_overall_declared_') or False
    if request.method == 'POST':
        results['_overall_declared_'] = True
        results['_overall_ranking_'] = ranking
        save_json(RESULTS_FILE, results)
        flash('Overall results declared.', 'success')
        return redirect(url_for('overall'))
    users = load_json(USERS_FILE)
    name_map = {uid: (u.get('profile',{}).get('school_name') or uid) for uid, u in users.items()}
    return render_template('admin/overall.html', ranking=ranking, declared=declared, name_map=name_map, events=events, breakdown=breakdown)


@app.route('/api/state')
@login_required(role='overall')
def api_state():
    return jsonify({
        'users': load_json(USERS_FILE),
        'events': load_json(EVENTS_FILE),
        'registrations': load_json(REGISTRATIONS_FILE),
        'submissions': load_json(SUBMISSIONS_FILE),
        'results': load_json(RESULTS_FILE),
    })

@app.template_filter('format_datetime')
def format_datetime(value, format='medium'):
    if not value:
        return ""
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if format == 'full':
        format = "%Y-%m-%d %H:%M:%S"
    elif format == 'medium':
        format = "%Y-%m-%d %H:%M"
    else:
        format = "%Y-%m-%d"
    return value.strftime(format)


if __name__ == '__main__':
    users = load_json(USERS_FILE)
    has_overall = any(u.get('role') == 'overall' for u in users.values())
    if not has_overall:
        admin_id = str(uuid.uuid4())
        salt = uuid.uuid4().hex
        default_email = 'admin@example.com'
        default_pwd = 'Admin@123'
        users[admin_id] = {
            'role': 'overall',
            'created_at': datetime.utcnow().isoformat(),
            'verified': True,
            'profile': {
                'school_name': 'Overall Admin',
                'school_address': '',
                'school_email': default_email,
                'teacher_name': 'Overall Admin',
                'teacher_phone': '',
                'teacher_email': default_email,
                'student_name': '',
                'student_email': '',
                'student_phone': ''
            },
            'assigned_events': [],
            'auth': {
                'salt': salt,
                'password_hash': hash_token(salt + default_pwd)
            }
        }
        save_json(USERS_FILE, users)
        print('[INFO] Seeded Overall Admin user:')
        print('  Email: admin@example.com')
        print('  Password: Admin@123')
    app.run(debug=True)
