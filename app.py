import contextvars, os, re, csv, io, json, sqlite3, hashlib, hmac, base64, secrets, smtplib, html, uuid, shutil, logging, threading
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Depends, UploadFile, File, Form, BackgroundTasks, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, EmailStr
import qrcode
from mailer import (mail_configured, smtp_configured, send_compesa_email, send_mail, send_mail_detailed,
                    build_mail, reset_email, is_deliverable, qr_png_bytes, confirmation_page, calendar_url,
                    public_url, transports, _now_ist as now_ist, gmail_oauth_url, gmail_exchange_code, gmail_api_configured, MailError)
import mailer
import persist
try:
    import cv2
    import numpy as np
except Exception:
    cv2 = None
    np = None
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.utils import ImageReader

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / '.env')
load_dotenv(BASE / 'compesa.env')   # the project ships its settings as compesa.env
DB = Path(os.getenv('COMPESA_DB_PATH', str(BASE / 'data' / 'compesa.db'))).expanduser()
STATIC = BASE / 'static'
UPLOADS = BASE / 'uploads'
ASSETS = STATIC / 'assets'
SECRET = os.getenv('COMPESA_SECRET', 'compesa-local-development-secret-change-me').encode()
DEV_RESET = os.getenv('COMPESA_DEV_RESET', 'true').lower() == 'true'
LOGIN_EMAILS = os.getenv('COMPESA_LOGIN_EMAILS', 'true').lower() != 'false'

app = FastAPI(title='COMPESA Event Intelligence Platform', version='2.0.0')
UPLOADS.mkdir(parents=True, exist_ok=True)
app.mount('/static', StaticFiles(directory=STATIC), name='static')
app.mount('/uploads', StaticFiles(directory=UPLOADS), name='uploads')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('compesa')
BACKUPS = DB.parent / 'backups'


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Catch anything a route didn't already handle so the person always gets a
    # clean JSON error instead of a raw server crash/traceback.
    logger.exception('Unhandled error on %s %s', request.method, request.url.path)
    return JSONResponse(status_code=500, content={'detail': 'Something went wrong on the server. Please try again. If this keeps happening, tell the admin what you were doing.'})


@app.exception_handler(sqlite3.IntegrityError)
async def integrity_error_handler(request: Request, exc: sqlite3.IntegrityError):
    logger.warning('Integrity error on %s %s: %s', request.method, request.url.path, exc)
    return JSONResponse(status_code=400, content={'detail': 'That record is linked to something that does not exist, or it already exists.'})


def now():
    return datetime.now(timezone.utc).isoformat()


# Every connection opened while serving a request is remembered here, so that if a route fails half-way
# (an exception before its own con.close()) the connection is rolled back and closed instead of leaving a
# write lock behind that makes the NEXT request fail with "database is locked".
_REQ_CONS = contextvars.ContextVar('compesa_request_connections', default=None)


@app.middleware('http')
async def release_db_connections(request: Request, call_next):
    bucket = []
    token_ = _REQ_CONS.set(bucket)
    try:
        return await call_next(request)
    finally:
        _REQ_CONS.reset(token_)
        for c_ in bucket:
            try: c_.rollback()
            except Exception: pass
            try: c_.close()
            except Exception: pass


def db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB, timeout=30, check_same_thread=False)
    _b = _REQ_CONS.get()
    if _b is not None: _b.append(con)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    con.execute('PRAGMA busy_timeout=30000')
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA synchronous=NORMAL')
    return con


def hash_pw(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 180000)
    return salt.hex() + ':' + key.hex()


def check_pw(pw, stored):
    try:
        s, k = stored.split(':')
        key = hashlib.pbkdf2_hmac('sha256', pw.encode(), bytes.fromhex(s), 180000)
        return hmac.compare_digest(key.hex(), k)
    except Exception:
        return False


def token(payload):
    raw = json.dumps(payload, separators=(',', ':')).encode()
    b = base64.urlsafe_b64encode(raw).decode().rstrip('=')
    sig = hmac.new(SECRET, b.encode(), hashlib.sha256).hexdigest()
    return b + '.' + sig


def decode_token(t):
    try:
        b, s = t.rsplit('.', 1)
        exp = hmac.new(SECRET, b.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(s, exp):
            return None
        raw = base64.urlsafe_b64decode(b + '=' * (-len(b) % 4))
        p = json.loads(raw)
        if p.get('exp', 0) < datetime.now().timestamp():
            return None
        return p
    except Exception:
        return None


def auth(request: Request):
    t = request.headers.get('Authorization', '').replace('Bearer ', '')
    p = decode_token(t) if t else None
    if not p:
        raise HTTPException(401, 'Authentication required')
    con = db()
    u = con.execute('select * from users where id=?', (p['uid'],)).fetchone()
    con.close()
    if not u:
        raise HTTPException(401, 'User not found')
    return dict(u)


def role_ok(user, roles):
    if user['role'] not in roles:
        raise HTTPException(403, 'Permission denied')


def audit(user, action, target='', detail=''):
    con = db()
    con.execute('insert into audit_logs(user_id,action,target,detail,created_at) values(?,?,?,?,?)',
                (user['id'], action, target, detail, now()))
    con.commit(); con.close()


def notify(uid, title, body, kind='SYSTEM'):
    con = db()
    con.execute('insert into notifications(user_id,title,body,kind,created_at,read) values(?,?,?,?,?,0)',
                (uid, title, body, kind, now()))
    con.commit(); con.close()


def public_user(u):
    return {k: u[k] for k in [
        'id','email','notification_email','name','prn','department','year','division',
        'role','phone','photo','skills','interests','privacy','points'
    ] if k in u}


INDEXES = [
    'create index if not exists ix_users_email on users(lower(email))',
    'create index if not exists ix_users_notif_email on users(lower(notification_email))',
    'create index if not exists ix_users_prn on users(prn)',
    'create index if not exists ix_users_role on users(role)',
    'create index if not exists ix_reg_user on registrations(user_id)',
    'create index if not exists ix_reg_event_status on registrations(event_id,status)',
    'create index if not exists ix_reg_qr on registrations(qr_token)',
    'create index if not exists ix_team_members_user on team_members(user_id)',
    'create index if not exists ix_notif_user on notifications(user_id,created_at)',
    'create index if not exists ix_cert_user on certificates(user_id)',
    'create index if not exists ix_cert_event on certificates(event_id)',
    'create index if not exists ix_att_user on attendance(user_id)',
    'create index if not exists ix_results_event on results(event_id)',
    'create index if not exists ix_problems_event on problems(event_id)',
    'create index if not exists ix_subs_problem on submissions(problem_id)',
    'create index if not exists ix_audit_created on audit_logs(created_at)',
    'create index if not exists ix_events_date on events(date,start_time)',
]
# (child table, column, parent table). SQLite cannot add FOREIGN KEY to an existing table without
# rebuilding it, so the same protection is enforced with triggers: a child row can never point at
# a user/event/team/... that does not exist. Existing rows are untouched.
FK_RULES = [
    ('registrations','user_id','users'),('registrations','event_id','events'),
    ('attendance','user_id','users'),('attendance','event_id','events'),
    ('certificates','user_id','users'),('certificates','event_id','events'),
    ('results','user_id','users'),('results','event_id','events'),
    ('feedback','user_id','users'),('feedback','event_id','events'),
    ('teams','event_id','events'),('team_members','team_id','teams'),('team_members','user_id','users'),
    ('notifications','user_id','users'),('submissions','problem_id','problems'),('submissions','user_id','users'),
    ('problems','event_id','events'),('event_announcements','event_id','events'),
    ('volunteers','event_id','events'),('password_resets','user_id','users'),
]


def ensure_integrity(con):
    for q in INDEXES:
        try: con.execute(q)
        except sqlite3.OperationalError: logger.exception('Index creation skipped: %s', q)
    for child,col,parent in FK_RULES:
        for ev in ('insert','update'):
            name=f'fk_{child}_{col}_{ev}'
            try:
                con.execute(f'''create trigger if not exists {name} before {ev} on {child}
                    for each row when new.{col} is not null and not exists (select 1 from {parent} where id=new.{col})
                    begin select raise(abort,'Linked {parent[:-1]} record does not exist'); end''')
            except sqlite3.OperationalError: logger.exception('Trigger creation skipped: %s', name)
    # Users own too much history to delete blindly: refuse while registrations still point at them.
    con.execute('''create trigger if not exists fk_users_delete before delete on users
        for each row when exists (select 1 from registrations where user_id=old.id)
        begin select raise(abort,'User still has registrations'); end''')
    con.commit()


def init_db():
    DB.parent.mkdir(exist_ok=True)
    UPLOADS.mkdir(exist_ok=True)
    ASSETS.mkdir(exist_ok=True)
    con = db(); c = con.cursor()
    c.executescript('''
    create table if not exists users(
      id integer primary key autoincrement,
      email text unique,password text,name text,prn text,department text,year text,division text,
      role text default 'student',phone text,photo text,skills text default '',interests text default '',
      privacy text default 'college',points integer default 0,notification_email text default '',created_at text
    );
    create table if not exists events(
      id integer primary key autoincrement,name text,description text,category text,date text,start_time text,end_time text,
      venue text,max_participants integer,team_size integer default 1,fee real default 0,deadline text,rules text,
      coordinators text,status text default 'OPEN',organization text default 'COMPESA',created_at text
    );
    create table if not exists registrations(
      id integer primary key autoincrement,reg_code text unique,user_id integer,event_id integer,team_id integer,
      status text,qr_token text,created_at text,approved_at text,payment_mode text default 'OFFLINE',payment_status text default 'NOT_REQUIRED',payment_reference text default '',unique(user_id,event_id)
    );
    create table if not exists teams(id integer primary key autoincrement,event_id integer,name text,invite_code text unique,leader_id integer,created_at text);
    create table if not exists team_members(id integer primary key autoincrement,team_id integer,user_id integer,role text,unique(team_id,user_id));
    create table if not exists notifications(id integer primary key autoincrement,user_id integer,title text,body text,kind text,created_at text,read integer default 0);
    create table if not exists certificates(id integer primary key autoincrement,cert_id text unique,user_id integer,event_id integer,issued_at text,hash text,public integer default 1,file_path text,source text default 'generated');
    create table if not exists results(id integer primary key autoincrement,event_id integer,user_id integer,position text,score real,mention text);
    create table if not exists attendance(id integer primary key autoincrement,event_id integer,user_id integer,scanned_at text,method text,unique(event_id,user_id));
    create table if not exists feedback(id integer primary key autoincrement,event_id integer,user_id integer,content text,rating integer,created_at text,unique(event_id,user_id));
    create table if not exists audit_logs(id integer primary key autoincrement,user_id integer,action text,target text,detail text,created_at text);
    create table if not exists email_logs(id integer primary key autoincrement,registration_id integer,user_id integer,to_email text,subject text,status text,error text,sent_at text,created_at text);
    create table if not exists venues(id integer primary key autoincrement,name text,building text,floor text,room text,capacity integer,facilities text,available integer default 1,address text default '',maps_url text default '',latitude real,longitude real);
    create table if not exists problems(id integer primary key autoincrement,event_id integer,title text,difficulty text,statement text,points integer default 100);
    create table if not exists submissions(id integer primary key autoincrement,problem_id integer,user_id integer,language text,code text,status text,score real,submitted_at text);
    create table if not exists password_resets(id integer primary key autoincrement,user_id integer,token_hash text unique,expires_at text,used integer default 0,created_at text);
    create table if not exists event_announcements(id integer primary key autoincrement,event_id integer,title text,body text,created_at text,created_by integer);
    create table if not exists payment_qrs(id integer primary key autoincrement,label text,upi_id text default '',image_path text,active integer default 1,created_by integer,created_at text);
    create table if not exists volunteers(id integer primary key autoincrement,name text,employee_prn text,email text,phone text,department text,event_id integer,position text,responsibilities text,shift text,status text default 'ACTIVE',notes text,created_at text,updated_at text);
    ''')
    c.execute('''create table if not exists email_outbox(id integer primary key autoincrement,kind text,user_id integer,registration_id integer,to_email text,params text,status text default 'PENDING',attempts integer default 0,next_attempt_at text,last_error text default '',log_id integer,created_at text,sent_at text)''')
    c.execute('create table if not exists app_settings(key text primary key,value text)')
    c.execute('create index if not exists ix_outbox_status on email_outbox(status,next_attempt_at)')
    # Lightweight migrations for databases created by older versions.
    for col, typ in [('notification_email','text default ""'),('photo','text'),('file_path','text'),('source','text default "generated"')]:
        try: c.execute(f'alter table users add column {col} {typ}') if col in ('notification_email','photo') else c.execute(f'alter table certificates add column {col} {typ}')
        except sqlite3.OperationalError: pass
    for table, cols in {
        'registrations':[('payment_mode','text default "OFFLINE"'),('payment_status','text default "NOT_REQUIRED"'),('payment_reference','text default ""'),('reference_person','text default ""'),('payment_qr_id','integer')],
        'users':[('notification_prefs','text default ""')],
        'events':[('live_status','text default "SCHEDULED"'),('live_title','text default ""'),('live_venue','text default ""'),('live_date','text default ""'),('live_start_time','text default ""'),('live_end_time','text default ""'),('current_round','text default ""'),('live_instructions','text default ""'),('emergency_message','text default ""'),('poster_path','text default ""'),('banner_path','text default ""')],
        'venues':[('address','text default ""'),('maps_url','text default ""'),('latitude','real'),('longitude','real')]
    }.items():
        for col, typ in cols:
            try: c.execute(f'alter table {table} add column {col} {typ}')
            except sqlite3.OperationalError: pass

    if not c.execute('select 1 from users limit 1').fetchone():
        users = [
            ('admin@compesa.local','Admin User','ADMIN001','Computer Engineering','3','A','super_admin','9876543210','Python,Java,React,AI','Coding,AI,Hackathon','admin@compesa.local'),
            ('coordinator@compesa.local','Event Coordinator','COORD001','Computer Engineering','4','A','event_coordinator','9876543211','Python,Event Management','Hackathon,Workshop','coordinator@compesa.local'),
            ('student@compesa.local','Rahul Patil','23CSE001','Computer Engineering','3','A','student','9876543212','Python,Java,React,AI/ML,Backend','Coding,AI,Hackathon,Workshop','student@compesa.local')
        ]
        for email,name,prn,dept,yr,div,role,phone,skills,interests,gmail in users:
            c.execute('insert into users(email,password,name,prn,department,year,division,role,phone,skills,interests,notification_email,created_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                      (email,hash_pw('Compesa@123'),name,prn,dept,yr,div,role,phone,skills,interests,gmail,now()))
    else:
        try:
            c.execute("update users set notification_email=email where coalesce(notification_email,'')='' ")
        except Exception: pass
    if not c.execute('select 1 from events limit 1').fetchone():
        c.execute('insert into events(name,description,category,date,start_time,end_time,venue,max_participants,team_size,fee,deadline,rules,coordinators,created_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                  ('CodeSprint 2026','Inter-college coding competition with live leaderboard.','Coding Competition','2026-10-10','10:00','16:00','Computer Lab 3',100,2,0,'2026-10-09T23:59','Bring college ID. Teams max 2. Fair-play rules apply.','Event Coordinator',now()))
        eid=c.lastrowid
        c.execute('insert into problems(event_id,title,difficulty,statement,points) values(?,?,?,?,?)',(eid,'Two Sum','Easy','Given an array and target, return indices of two numbers whose sum is target.',100))
        c.execute('insert into problems(event_id,title,difficulty,statement,points) values(?,?,?,?,?)',(eid,'Graph Paths','Medium','Find the number of paths from source to destination in a directed acyclic graph.',200))
    if not c.execute('select 1 from venues limit 1').fetchone():
        for v in [('Lab 1','Block A','1','A-101',60,'Computers,Wi-Fi,Projector'),('Lab 2','Block A','1','A-102',60,'Computers,Wi-Fi'),('Seminar Hall','Block B','2','B-201',120,'Projector,Audio,AC'),('Auditorium','Main Block','Ground','G-001',500,'Projector,Audio,Stage')]:
            c.execute('insert into venues(name,building,floor,room,capacity,facilities) values(?,?,?,?,?,?)',v)
    if not c.execute('select 1 from payment_qrs limit 1').fetchone() and (ASSETS/'payment_qr.png').exists():
        c.execute('insert into payment_qrs(label,upi_id,image_path,active,created_at) values(?,?,?,?,?)',('Default payment QR','','/static/assets/payment_qr.png',1,now()))
    con.commit()
    ensure_integrity(con)
    con.close()


# Pull the newest data from the external Postgres BEFORE SQLite is opened (no-op without DATABASE_URL).
persist.restore_on_boot(DB, UPLOADS)
init_db()


def _snapshot_db(dest: Path):
    """Make a consistent copy of the live database using SQLite's own backup API.
    Safe to call even while the server is running in WAL mode."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    src_con = sqlite3.connect(DB)
    dest_con = sqlite3.connect(dest)
    with dest_con:
        src_con.backup(dest_con)
    src_con.close(); dest_con.close()


def _backup(tag='manual', keep=10):
    BACKUPS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    dest = BACKUPS / f'compesa_{tag}_{stamp}.db'
    _snapshot_db(dest)
    for old in sorted(BACKUPS.glob(f'compesa_{tag}_*.db'))[:-keep]:
        try: old.unlink()
        except Exception: pass
    return dest


try:
    # A free safety net: snapshot the database every time the app boots, so an
    # admin mistake or a bad redeploy never loses more than "since the last boot".
    # This does NOT protect against the hosting disk itself being wiped on a free
    # plan (see README) — use Admin > Database (or /api/admin/backup) for that.
    _backup('startup', keep=5)
except Exception:
    logger.exception('Automatic startup database backup failed')

persist.start()   # background mirror of the database + uploads to Postgres (no-op without DATABASE_URL)


class Login(BaseModel):
    email: str
    password: str

class StudentRegister(BaseModel):
    name: str
    prn: str
    email: str
    notification_email: str
    department: str
    year: str
    division: str
    phone: str
    password: str
    skills: str = ''
    interests: str = ''

class ForgotPassword(BaseModel):
    email: str

class ResetPassword(BaseModel):
    token: str
    password: str

class AdminRecover(BaseModel):
    email: str
    recovery_key: str
    new_password: str

class EventFeeIn(BaseModel):
    fee: float = Field(default=0, ge=0)


class EventIn(BaseModel):
    name: str; description: str=''; category: str='Workshop'; date: str; start_time: str='10:00'; end_time: str='12:00';
    venue: str=''; max_participants: int=50; team_size: int=1; fee: float=0; deadline: str=''; rules: str=''; coordinators: str=''

class EventLiveIn(BaseModel):
    live_status: str='SCHEDULED'; live_title: str=''; live_venue: str=''; live_date: str=''; live_start_time: str=''; live_end_time: str=''; current_round: str=''; live_instructions: str=''; emergency_message: str=''

class VenueIn(BaseModel):
    name: str; building: str=''; floor: str=''; room: str=''; capacity: int=0; facilities: str=''; available: bool=True; address: str=''; maps_url: str=''; latitude: Optional[float]=None; longitude: Optional[float]=None

class VolunteerIn(BaseModel):
    name: str; employee_prn: str=''; email: str=''; phone: str=''; department: str=''; event_id: Optional[int]=None; position: str='Coordinator'; responsibilities: str=''; shift: str=''; status: str='ACTIVE'; notes: str=''

class ProfileIn(BaseModel):
    name: str; prn: str=''; department: str=''; year: str=''; division: str=''; phone: str=''; skills: str=''; interests: str=''; privacy: str='college'; notification_email: str=''

class StatusIn(BaseModel): status: str
class FeedbackIn(BaseModel): rating: int=5; content: str=''
class TeamIn(BaseModel): event_id: int; name: str
class JoinTeam(BaseModel): invite_code: str
class ResultIn(BaseModel): event_id: int; user_id: int; position: str; score: float=0; mention: str=''
class SubmitIn(BaseModel): problem_id: int; language: str='python'; code: str
class Announcement(BaseModel): title: str; body: str; event_id: Optional[int]=None


@app.get('/', response_class=HTMLResponse)
def home(): return (STATIC/'index.html').read_text(encoding='utf8')

@app.get('/manifest.json')
def manifest(): return FileResponse(STATIC/'manifest.json')

@app.get('/service-worker.js')
def sw(): return FileResponse(STATIC/'service-worker.js')


@app.post('/api/auth/login')
def login(x: Login, request: Request, bg: BackgroundTasks):
    con=db(); u=con.execute('select * from users where lower(email)=lower(?) or lower(notification_email)=lower(?)',(x.email.strip(),x.email.strip())).fetchone(); con.close()
    if not u or not check_pw(x.password,u['password']): raise HTTPException(401,'Invalid email or password')
    # "Login successful" e-mail, sent in the background so a slow SMTP server never delays the login itself.
    to=(u['notification_email'] or u['email'] or '').strip()
    if LOGIN_EMAILS and mail_configured() and is_deliverable(to):
        ip,ua=_client_info(request)
        enqueue_email('login',u['id'],to,{'user':{'name':u['name']},'ip':ip,'device':ua,'when':now_ist()},subject='COMPESA — Login successful')
    return {'token':token({'uid':u['id'],'exp':(datetime.now()+timedelta(days=2)).timestamp()}),'user':public_user(dict(u))}

@app.post('/api/auth/register')
def student_register(x: StudentRegister, bg: BackgroundTasks):
    if len(x.password) < 8: raise HTTPException(400,'Password must be at least 8 characters')
    if not x.name.strip(): raise HTTPException(400,'Full name is required')
    if not x.prn.strip(): raise HTTPException(400,'PRN / Roll No. is required')
    if not re.fullmatch(r'\d{10}', x.phone.strip()): raise HTTPException(400,'Enter a valid 10-digit student contact number')
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', x.notification_email): raise HTTPException(400,'Enter a valid Gmail/notification email')
    con=db()
    if con.execute('select 1 from users where lower(email)=lower(?) or lower(notification_email)=lower(?)',(x.email.strip(),x.notification_email.strip())).fetchone(): con.close(); raise HTTPException(409,'Email already registered')
    # PRN / Roll No. is intentionally NOT unique: several students may share one.
    cur=con.execute('insert into users(email,password,name,prn,department,year,division,role,phone,skills,interests,notification_email,created_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (x.email.strip(),hash_pw(x.password),x.name.strip(),x.prn.strip(),x.department.strip(),x.year.strip(),x.division.strip(),'student',x.phone.strip(),x.skills.strip(),x.interests.strip(),x.notification_email.strip(),now()))
    uid=cur.lastrowid; con.commit(); con.close()
    to=x.notification_email.strip()
    email_queued = bool(mail_configured() and is_deliverable(to))
    if email_queued:
        enqueue_email('welcome',uid,to,{'user':{'name':x.name.strip(),'email':x.email.strip(),'prn':x.prn.strip()}},subject='Welcome to COMPESA — account created')
    return {'message':'Student account created','user_id':uid,'email_queued':email_queued}

@app.post('/api/auth/forgot-password')
def forgot_password(x: ForgotPassword, request: Request):
    con=db(); u=con.execute('select * from users where lower(email)=lower(?) or lower(notification_email)=lower(?)',(x.email.strip(),x.email.strip())).fetchone()
    # Always return a generic message to avoid account enumeration.
    if not u:
        con.close(); return {'message':'If the account exists, a password reset link has been prepared.'}
    raw=secrets.token_urlsafe(32); th=hashlib.sha256(raw.encode()).hexdigest(); exp=datetime.now(timezone.utc)+timedelta(minutes=30)
    con.execute('insert into password_resets(user_id,token_hash,expires_at,created_at) values(?,?,?,?)',(u['id'],th,exp.isoformat(),now())); con.commit(); con.close()
    reset_url=(public_url() or str(request.base_url).rstrip('/'))+f'/?reset={raw}'
    sent=False; error=''
    if mail_configured():
        sent,error=send_mail(u['notification_email'] or u['email'],reset_email({'name':u['name']},reset_url),attempts=1)
        if not sent: logger.warning('Password reset e-mail failed: %s',error)
    result={'message':'If the account exists, a password reset link has been prepared.','email_sent':sent}
    if DEV_RESET and not sent: result['development_reset_url']=reset_url
    return result

@app.post('/api/auth/reset-password')
def reset_password(x: ResetPassword):
    if len(x.password)<8: raise HTTPException(400,'Password must be at least 8 characters')
    th=hashlib.sha256(x.token.encode()).hexdigest(); con=db(); r=con.execute('select * from password_resets where token_hash=? and used=0 order by id desc limit 1',(th,)).fetchone()
    if not r or datetime.fromisoformat(r['expires_at']) < datetime.now(timezone.utc): con.close(); raise HTTPException(400,'Reset link is invalid or expired')
    con.execute('update users set password=? where id=?',(hash_pw(x.password),r['user_id'])); con.execute('update password_resets set used=1 where id=?',(r['id'],)); con.commit(); con.close(); return {'message':'Password changed successfully. You can now log in.'}

@app.post('/api/auth/admin-recover-password')
def admin_recover_password(x: AdminRecover):
    """Emergency account recovery that does not depend on email/SMTP at all.
    Disabled unless COMPESA_ADMIN_RECOVERY_KEY is set in the environment — set it
    once, keep it secret, and use it only if you are locked out of every account
    and cannot receive a reset email."""
    recovery_key = os.getenv('COMPESA_ADMIN_RECOVERY_KEY', '')
    if not recovery_key:
        raise HTTPException(503, 'Admin recovery is not turned on for this server. Set COMPESA_ADMIN_RECOVERY_KEY in your .env to enable it.')
    if not hmac.compare_digest(x.recovery_key.encode(), recovery_key.encode()):
        raise HTTPException(401, 'Incorrect recovery key')
    if len(x.new_password) < 8:
        raise HTTPException(400, 'Password must be at least 8 characters')
    con = db()
    u = con.execute('select * from users where lower(email)=lower(?) or lower(notification_email)=lower(?)', (x.email.strip(), x.email.strip())).fetchone()
    if not u:
        con.close(); raise HTTPException(404, 'No account found with that email')
    con.execute('update users set password=? where id=?', (hash_pw(x.new_password), u['id']))
    con.commit(); con.close()
    audit({'id': u['id']}, 'ADMIN_RECOVERY_RESET', str(u['id']), f'Password reset via recovery key for {u["email"]}')
    return {'message': f'Password for {u["email"]} has been reset. You can log in now.'}

@app.get('/api/auth/me')
def me(user=Depends(auth)): return public_user(user)


@app.get('/api/dashboard')
def dashboard(user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator','volunteer'])
    con=db()
    data={k:con.execute(q).fetchone()[0] for k,q in {
        'students':"select count(*) from users where role='student'",'events':'select count(*) from events',
        'upcoming':"select count(*) from events where date>=date('now')",'registrations':'select count(*) from registrations',
        'pending':"select count(*) from registrations where status='PENDING'",'certificates':'select count(*) from certificates',
        'attendance':'select count(*) from attendance','revenue':"select coalesce(sum(e.fee),0) from registrations r join events e on e.id=r.event_id where r.status='APPROVED'"
    }.items()}
    cats=[dict(r) for r in con.execute('select category,count(*) count from events group by category order by count desc').fetchall()]
    months=[dict(r) for r in con.execute("select substr(created_at,1,7) month,count(*) count from registrations group by month order by month").fetchall()]
    depts=[dict(r) for r in con.execute("select department,count(*) count from registrations r join users u on u.id=r.user_id group by department order by count desc").fetchall()]
    con.close(); return {**data,'categories':cats,'months':months,'departments':depts}


def _remove_event_image(path):
    if not path: return
    try:
        rel = str(path).lstrip('/').replace('\\','/')
        if rel.startswith('uploads/'):
            target = BASE / rel
            if target.exists() and target.is_file(): target.unlink()
    except Exception:
        pass


def _validate_image(upload: UploadFile):
    allowed = {'image/jpeg','image/png','image/webp','image/gif'}
    if upload.content_type not in allowed:
        raise HTTPException(400, 'Only JPG, PNG, WEBP or GIF images are allowed')


async def _save_event_image(upload: UploadFile, eid: int, kind: str):
    _validate_image(upload)
    ext = Path(upload.filename or '').suffix.lower()
    if ext not in {'.jpg','.jpeg','.png','.webp','.gif'}:
        ext = '.jpg' if upload.content_type == 'image/jpeg' else '.png'
    data = await upload.read()
    if len(data) > 8 * 1024 * 1024:
        raise HTTPException(400, 'Image must be 8 MB or smaller')
    name = f'event_{eid}_{kind}_{uuid.uuid4().hex}{ext}'
    path = UPLOADS / name
    path.write_bytes(data)
    return f'/uploads/{name}'


@app.get('/api/public/events')
def public_events():
    con=db(); rows=con.execute("select id,name,description,category,date,start_time,end_time,venue,status,poster_path,banner_path from events order by date,start_time").fetchall(); con.close(); return [dict(r) for r in rows]

@app.get('/api/public/results')
def public_results():
    con=db(); rows=con.execute("select r.position,r.score,r.mention,u.name,e.name event_name,e.date from results r join users u on u.id=r.user_id join events e on e.id=r.event_id order by e.date desc,r.score desc limit 100").fetchall(); con.close(); return [dict(r) for r in rows]

@app.get('/api/events')
def events(q:str='',category:str='',user=Depends(auth)):
    con=db(); rows=con.execute('select * from events where name like ? and category like ? order by date,start_time',(f'%{q}%',f'%{category}%')).fetchall(); out=[]
    for e in rows:
        d=dict(e)
        if user['role']=='student':
            # Students never receive participant counts or raw capacity/registration lists.
            d.pop('max_participants',None); d.pop('team_size',None)
            d['availability']='Open' if d['status']=='OPEN' else d['status'].title(); d['team_enabled']=bool(e['team_size'] and e['team_size']>1)
        out.append(d)
    con.close(); return out

@app.post('/api/events')
def create_event(x:EventIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db()
    conflict=con.execute("select id from events where date=? and venue=? and start_time < ? and end_time > ?",(x.date,x.venue,x.end_time,x.start_time)).fetchone()
    if conflict: con.close(); raise HTTPException(409,'Venue conflict: another event overlaps this time slot')
    cur=con.execute('insert into events(name,description,category,date,start_time,end_time,venue,max_participants,team_size,fee,deadline,rules,coordinators,created_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (x.name,x.description,x.category,x.date,x.start_time,x.end_time,x.venue,x.max_participants,x.team_size,x.fee,x.deadline,x.rules,x.coordinators or user['name'],now()))
    eid=cur.lastrowid; con.commit(); con.close(); audit(user,'CREATE_EVENT',str(eid),x.name); return {'id':eid,'message':'Event created'}

@app.delete('/api/events/{eid}')
def delete_event(eid:int,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin'])
    con=db()
    try:
        event=con.execute('select id,name,poster_path,banner_path from events where id=?',(eid,)).fetchone()
        if not event:
            raise HTTPException(404,'Event not found')
        # Remove dependent records first because the existing schema predates
        # foreign-key cascades. Everything is committed as one transaction.
        con.execute('delete from email_logs where registration_id in (select id from registrations where event_id=?)',(eid,))
        con.execute('delete from team_members where team_id in (select id from teams where event_id=?)',(eid,))
        con.execute('delete from registrations where event_id=?',(eid,))
        con.execute('delete from teams where event_id=?',(eid,))
        con.execute('delete from certificates where event_id=?',(eid,))
        con.execute('delete from results where event_id=?',(eid,))
        con.execute('delete from attendance where event_id=?',(eid,))
        con.execute('delete from feedback where event_id=?',(eid,))
        con.execute('delete from event_announcements where event_id=?',(eid,))
        con.execute('delete from volunteers where event_id=?',(eid,))
        problem_ids=[r[0] for r in con.execute('select id from problems where event_id=?',(eid,)).fetchall()]
        if problem_ids:
            marks=','.join('?' for _ in problem_ids)
            con.execute(f'delete from submissions where problem_id in ({marks})',problem_ids)
        con.execute('delete from problems where event_id=?',(eid,))
        con.execute('delete from events where id=?',(eid,))
        con.commit()
        _remove_event_image(event['poster_path'])
        _remove_event_image(event['banner_path'])
    except HTTPException:
        con.rollback(); con.close(); raise
    except Exception:
        con.rollback(); con.close(); raise
    con.close()
    audit(user,'DELETE_EVENT',str(eid),event['name'])
    return {'message':'Event deleted successfully','event_id':eid}


@app.post('/api/events/{eid}/images')
async def update_event_images(eid:int, poster: UploadFile | None = File(None), banner: UploadFile | None = File(None), user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator'])
    con=db(); e=con.execute('select id,poster_path,banner_path from events where id=?',(eid,)).fetchone()
    if not e:
        con.close(); raise HTTPException(404,'Event not found')
    old_poster=e['poster_path']; old_banner=e['banner_path']
    try:
        poster_path = old_poster
        banner_path = old_banner
        if poster and poster.filename:
            poster_path = await _save_event_image(poster,eid,'poster')
        if banner and banner.filename:
            banner_path = await _save_event_image(banner,eid,'banner')
        con.execute('update events set poster_path=?,banner_path=? where id=?',(poster_path,banner_path,eid))
        con.commit()
    except HTTPException:
        con.rollback(); con.close(); raise
    except Exception:
        con.rollback(); con.close(); raise
    con.close()
    if poster and poster.filename and old_poster and old_poster != poster_path: _remove_event_image(old_poster)
    if banner and banner.filename and old_banner and old_banner != banner_path: _remove_event_image(old_banner)
    audit(user,'UPDATE_EVENT_IMAGES',str(eid),'Poster/banner updated')
    return {'message':'Event images updated','poster_path':poster_path,'banner_path':banner_path}


@app.put('/api/events/{eid}')
def update_event(eid:int,x:EventIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db()
    exists=con.execute('select id from events where id=?',(eid,)).fetchone()
    if not exists: con.close(); raise HTTPException(404,'Event not found')
    conflict=con.execute("select id from events where id!=? and date=? and venue=? and start_time < ? and end_time > ?",(eid,x.date,x.venue,x.end_time,x.start_time)).fetchone()
    if conflict: con.close(); raise HTTPException(409,'Venue conflict: another event overlaps this time slot')
    con.execute('update events set name=?,description=?,category=?,date=?,start_time=?,end_time=?,venue=?,max_participants=?,team_size=?,fee=?,deadline=?,rules=?,coordinators=? where id=?',(x.name,x.description,x.category,x.date,x.start_time,x.end_time,x.venue,x.max_participants,x.team_size,x.fee,x.deadline,x.rules,x.coordinators or user['name'],eid)); con.commit(); con.close(); audit(user,'UPDATE_EVENT',str(eid),x.name); return {'message':'Event updated'}

@app.patch('/api/events/{eid}/fee')
def update_event_fee(eid:int,x:EventFeeIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator'])
    con=db()
    exists=con.execute('select name from events where id=?',(eid,)).fetchone()
    if not exists:
        con.close(); raise HTTPException(404,'Event not found')
    con.execute('update events set fee=? where id=?',(float(x.fee),eid))
    con.commit(); con.close()
    audit(user,'UPDATE_EVENT_FEE',str(eid),f'{exists["name"]}: ₹{float(x.fee):.2f}')
    return {'message':'Event fee updated','fee':float(x.fee)}


@app.patch('/api/events/{eid}/live')
def update_live_event(eid:int,x:EventLiveIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']);
    if x.live_status.upper() not in ('SCHEDULED','LIVE','PAUSED','ENDED'): raise HTTPException(400,'Invalid live status')
    con=db(); e=con.execute('select * from events where id=?',(eid,)).fetchone()
    if not e: con.close(); raise HTTPException(404,'Event not found')
    con.execute('update events set live_status=?,live_title=?,live_venue=?,live_date=?,live_start_time=?,live_end_time=?,current_round=?,live_instructions=?,emergency_message=? where id=?',(x.live_status.upper(),x.live_title,x.live_venue,x.live_date,x.live_start_time,x.live_end_time,x.current_round,x.live_instructions,x.emergency_message,eid)); con.commit(); con.close()
    if x.emergency_message or x.live_status.upper()=='LIVE':
        con=db(); ids=[r[0] for r in con.execute('select distinct user_id from registrations where event_id=? and status in (\'APPROVED\',\'COMPLETED\')',(eid,)).fetchall()]; con.close()
        body=x.emergency_message or f'{x.live_title or e["name"]} is now LIVE.'
        for uid in ids: notify(uid,f'🔴 {x.live_title or e["name"]}',body,'LIVE_EVENT')
    audit(user,'UPDATE_LIVE_EVENT',str(eid),f'{x.live_status}; round={x.current_round}')
    return {'message':'Live event updated'}

@app.get('/api/events/{eid}/live')
def get_live_event(eid:int,user=Depends(auth)):
    con=db(); e=con.execute('select * from events where id=?',(eid,)).fetchone();
    if not e: con.close(); raise HTTPException(404,'Event not found')
    if user['role']=='student':
        reg=con.execute("select 1 from registrations where event_id=? and user_id=? and status in ('APPROVED','COMPLETED')",(eid,user['id'])).fetchone()
        if not reg: con.close(); raise HTTPException(403,'Live event details are available only to registered students')
    d={k:e[k] for k in ['id','name','venue','date','start_time','end_time','live_status','live_title','live_venue','live_date','live_start_time','live_end_time','current_round','live_instructions','emergency_message']}; con.close(); return d

@app.post('/api/venues')
def create_venue(x:VenueIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); cur=con.execute('insert into venues(name,building,floor,room,capacity,facilities,available,address,maps_url,latitude,longitude) values(?,?,?,?,?,?,?,?,?,?,?)',(x.name,x.building,x.floor,x.room,x.capacity,x.facilities,int(x.available),x.address,x.maps_url,x.latitude,x.longitude)); con.commit(); vid=cur.lastrowid; con.close(); audit(user,'CREATE_VENUE',str(vid),x.name); return {'id':vid,'message':'Venue created'}

@app.patch('/api/venues/{vid}')
def update_venue(vid:int,x:VenueIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db();
    if not con.execute('select id from venues where id=?',(vid,)).fetchone(): con.close(); raise HTTPException(404,'Venue not found')
    con.execute('update venues set name=?,building=?,floor=?,room=?,capacity=?,facilities=?,available=?,address=?,maps_url=?,latitude=?,longitude=? where id=?',(x.name,x.building,x.floor,x.room,x.capacity,x.facilities,int(x.available),x.address,x.maps_url,x.latitude,x.longitude,vid)); con.commit(); con.close(); audit(user,'UPDATE_VENUE',str(vid),x.name); return {'message':'Venue updated'}

@app.delete('/api/venues/{vid}')
def delete_venue(vid:int,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db();
    if con.execute('select 1 from events where venue=(select name from venues where id=?)',(vid,)).fetchone(): con.close(); raise HTTPException(409,'Venue is assigned to an event and cannot be removed')
    con.execute('delete from venues where id=?',(vid,)); con.commit(); con.close(); audit(user,'DELETE_VENUE',str(vid),'Venue removed'); return {'message':'Venue removed'}

@app.get('/api/volunteers')
def volunteers(user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); rows=con.execute("select v.*,e.name event_name from volunteers v left join events e on e.id=v.event_id order by v.created_at desc").fetchall(); con.close(); return [dict(r) for r in rows]

@app.post('/api/volunteers')
def create_volunteer(x:VolunteerIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); cur=con.execute('insert into volunteers(name,employee_prn,email,phone,department,event_id,position,responsibilities,shift,status,notes,created_at,updated_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?)',(x.name,x.employee_prn,x.email,x.phone,x.department,x.event_id,x.position,x.responsibilities,x.shift,x.status,x.notes,now(),now())); con.commit(); vid=cur.lastrowid; con.close(); audit(user,'CREATE_VOLUNTEER',str(vid),f'{x.name} / {x.position}'); return {'id':vid,'message':'Volunteer added'}

@app.patch('/api/volunteers/{vid}')
def update_volunteer(vid:int,x:VolunteerIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db();
    if not con.execute('select id from volunteers where id=?',(vid,)).fetchone(): con.close(); raise HTTPException(404,'Volunteer not found')
    con.execute('update volunteers set name=?,employee_prn=?,email=?,phone=?,department=?,event_id=?,position=?,responsibilities=?,shift=?,status=?,notes=?,updated_at=? where id=?',(x.name,x.employee_prn,x.email,x.phone,x.department,x.event_id,x.position,x.responsibilities,x.shift,x.status,x.notes,now(),vid)); con.commit(); con.close(); audit(user,'UPDATE_VOLUNTEER',str(vid),f'{x.name} / {x.position}'); return {'message':'Volunteer updated'}

@app.delete('/api/volunteers/{vid}')
def delete_volunteer(vid:int,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); con.execute('delete from volunteers where id=?',(vid,)); con.commit(); con.close(); audit(user,'DELETE_VOLUNTEER',str(vid),'Volunteer removed'); return {'message':'Volunteer removed'}

@app.get('/api/events/{eid}')
def event(eid:int,user=Depends(auth)):
    con=db(); e=con.execute('select * from events where id=?',(eid,)).fetchone()
    if not e: con.close(); raise HTTPException(404,'Event not found')
    d={'event':dict(e)}
    if user['role']!='student':
        regs=con.execute("select r.*,u.name,u.email,u.notification_email,u.prn,u.department,u.year,u.division from registrations r join users u on u.id=r.user_id where r.event_id=? order by r.created_at desc",(eid,)).fetchall()
        d['registrations']=[dict(r) for r in regs]
    con.close(); return d


@app.post('/api/registrations/{eid}')
def register(eid:int, team_id: Optional[int]=None, payment_mode: str='OFFLINE', payment_reference: str='', reference_person: str='', payment_qr_id: Optional[int]=None, user=Depends(auth)):
    role_ok(user,['student']); con=db(); e=con.execute('select * from events where id=?',(eid,)).fetchone()
    if not e: con.close(); raise HTTPException(404,'Event not found')
    if e['deadline'] and e['deadline'] < now(): con.close(); raise HTTPException(400,'Registration deadline has passed')
    if con.execute('select 1 from registrations where user_id=? and event_id=?',(user['id'],eid)).fetchone(): con.close(); raise HTTPException(409,'Already registered')
    payment_mode=(payment_mode or 'OFFLINE').upper()
    if payment_mode not in ('ONLINE','OFFLINE'): payment_mode='OFFLINE'
    fee=float(e['fee'] or 0); reference_person=' '.join((reference_person or '').split()); payment_reference=(payment_reference or '').strip()
    # Offline / desk registration: the reference person's name is mandatory.
    if payment_mode=='OFFLINE' and len(reference_person)<2:
        con.close(); raise HTTPException(400,'Reference person name is required for offline (desk) registration')
    if len(reference_person)>120: con.close(); raise HTTPException(400,'Reference person name is too long')
    if payment_mode=='ONLINE' and fee>0:
        if not payment_reference: con.close(); raise HTTPException(400,'Enter the online payment reference / transaction ID')
        if payment_qr_id is not None and not con.execute('select 1 from payment_qrs where id=?',(payment_qr_id,)).fetchone(): payment_qr_id=None
    else:
        payment_qr_id=None
    code=f"CMP-{datetime.now().year%100}-{secrets.token_hex(3).upper()}"; qr=secrets.token_urlsafe(32)
    payment_status='PENDING' if payment_mode=='ONLINE' and fee>0 else ('NOT_REQUIRED' if fee<=0 else 'PAY_AT_DESK')
    # Seat check and insert happen inside ONE write lock, so two students can never both take the last seat.
    try:
        con.execute('BEGIN IMMEDIATE')
        if con.execute('select 1 from registrations where user_id=? and event_id=?',(user['id'],eid)).fetchone():
            con.rollback(); con.close(); raise HTTPException(409,'Already registered')
        count=con.execute("select count(*) from registrations where event_id=? and status in ('PENDING','APPROVED')",(eid,)).fetchone()[0]
        status='PENDING' if count < e['max_participants'] else 'WAITLISTED'
        con.execute('insert into registrations(reg_code,user_id,event_id,team_id,status,qr_token,created_at,payment_mode,payment_status,payment_reference,reference_person,payment_qr_id) values(?,?,?,?,?,?,?,?,?,?,?,?)',(code,user['id'],eid,team_id,status,qr,now(),payment_mode,payment_status,payment_reference,reference_person,payment_qr_id)); con.commit(); con.close()
    except HTTPException: raise
    except sqlite3.IntegrityError:
        con.rollback(); con.close(); raise HTTPException(409,'Already registered')
    except Exception:
        try: con.rollback(); con.close()
        except Exception: pass
        raise
    notify(user['id'],'Registration received',f"{e['name']} registration is {status}.",'REGISTRATION')
    return {'status':status,'registration_id':code,'payment_mode':payment_mode,'payment_status':payment_status,'fee':fee,'reference_person':reference_person}

@app.get('/api/registrations/me')
def my_regs(user=Depends(auth)):
    con=db(); rows=con.execute('select r.*,e.name event_name,e.category,e.date,e.start_time,e.end_time,e.venue,e.description,e.rules from registrations r join events e on e.id=r.event_id where r.user_id=? order by e.date desc',(user['id'],)).fetchall(); con.close(); return [dict(r) for r in rows]

@app.get('/api/registrations')
def all_regs(status:str='',department:str='',year:str='',division:str='',user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator','volunteer']); con=db()
    rows=con.execute("select r.*,u.name,u.email,u.notification_email,u.prn,u.department,u.year,u.division,e.name event_name,e.category,e.date,e.start_time,e.end_time,e.venue from registrations r join users u on u.id=r.user_id join events e on e.id=r.event_id where r.status like ? and u.department like ? and u.year like ? and u.division like ? order by r.created_at desc",(f'%{status}%',f'%{department}%',f'%{year}%',f'%{division}%')).fetchall(); con.close(); return [dict(r) for r in rows]


def log_email(registration_id,user_id,to_email,subject,status,error=''):
    con=db(); con.execute('insert into email_logs(registration_id,user_id,to_email,subject,status,error,sent_at,created_at) values(?,?,?,?,?,?,?,?)',(registration_id,user_id,to_email,subject,status,error,now() if status=='SENT' else None,now())); con.commit(); con.close()


def deliver(user_id, to_email, mail, registration_id=None):
    """Send one e-mail and record the result in email_logs (safe to run as a background task)."""
    try:
        ok, err = send_mail(to_email, mail)
        log_email(registration_id, user_id, to_email, mail['subject'], 'SENT' if ok else ('NOT_CONFIGURED' if 'not configured' in err.lower() else 'FAILED'), err)
        if not ok: logger.warning('E-mail to %s failed: %s', to_email, err)
        return ok, err
    except Exception as ex:
        logger.exception('E-mail delivery crashed')
        return False, f'{type(ex).__name__}: {ex}'


def _client_info(request: Request):
    ip = (request.headers.get('x-forwarded-for') or '').split(',')[0].strip() or (request.client.host if request.client else '')
    return ip, request.headers.get('user-agent', '')


# ----------------------------------------------------------------------------- e-mail outbox
# Every automatic e-mail is written to the database first and sent by a background worker. If Gmail / the
# network fails the mail is retried later (30s, 2m, 10m, 30m, 2h) instead of being lost, and an app restart
# does not forget pending mails.
OUTBOX_BACKOFF = [30, 120, 600, 1800, 7200]
_outbox_wake = threading.Event()


def enqueue_email(kind, user_id, to_email, params, registration_id=None, subject=''):
    ts = now()
    con = db()
    try:
        cur = con.execute('insert into email_logs(registration_id,user_id,to_email,subject,status,error,sent_at,created_at) values(?,?,?,?,?,?,?,?)',
                          (registration_id, user_id, to_email, subject, 'QUEUED', '', None, ts))
        log_id = cur.lastrowid
        con.execute('insert into email_outbox(kind,user_id,registration_id,to_email,params,status,attempts,next_attempt_at,last_error,log_id,created_at) values(?,?,?,?,?,?,?,?,?,?,?)',
                    (kind, user_id, registration_id, to_email, json.dumps(params), 'PENDING', 0, ts, '', log_id, ts))
        con.commit()
    finally:
        con.close()
    _outbox_wake.set()


def _process_outbox_once(limit=5):
    con = db()
    try:
        rows = [dict(r) for r in con.execute("select * from email_outbox where status='PENDING' and next_attempt_at<=? order by id limit ?", (now(), limit)).fetchall()]
    finally:
        con.close()
    for r in rows:
        try:
            ok, err, transient = send_mail_detailed(r['to_email'], build_mail(r['kind'], json.loads(r['params'])))
        except Exception as ex:
            logger.exception('Could not build/send queued e-mail %s', r['id'])
            ok, err, transient = False, f'{type(ex).__name__}: {ex}', False
        attempts = r['attempts'] + 1
        if ok:
            status, next_at, log_status = 'SENT', None, 'SENT'
        elif transient and attempts <= len(OUTBOX_BACKOFF):
            status, log_status = 'PENDING', 'RETRYING'
            next_at = (datetime.now(timezone.utc) + timedelta(seconds=OUTBOX_BACKOFF[attempts - 1])).isoformat()
        else:
            status, next_at = 'FAILED', None
            log_status = 'NOT_CONFIGURED' if 'not configured' in err.lower() else 'FAILED'
        con = db()
        try:
            con.execute('update email_outbox set status=?,attempts=?,next_attempt_at=?,last_error=?,sent_at=? where id=?',
                        (status, attempts, next_at, err[:500], now() if ok else None, r['id']))
            con.execute('update email_logs set status=?,error=?,sent_at=? where id=?',
                        (log_status, '' if ok else err[:500], now() if ok else None, r['log_id']))
            con.commit()
        finally:
            con.close()
        if not ok:
            logger.warning('E-mail to %s failed (attempt %s, %s): %s', r['to_email'], attempts, status, err)
    return len(rows)


def _outbox_worker():
    while True:
        _outbox_wake.clear()
        try:
            if _process_outbox_once() >= 5:
                continue
        except Exception:
            logger.exception('E-mail outbox worker error')
        _outbox_wake.wait(timeout=5)


threading.Thread(target=_outbox_worker, name='compesa-outbox', daemon=True).start()


@app.on_event('shutdown')
def _on_shutdown():
    persist.stop_and_flush()   # last upload to Postgres so a normal stop/restart loses nothing


# ----------------------------------------------------------------------------- Connect Gmail (OAuth, no tokens on disk)
# Admin presses "Connect Gmail" -> Google consent -> the refresh token is saved in the DATABASE (which is mirrored to
# Postgres), so it survives restarts on any host. GMAIL_CLIENT_ID / GMAIL_CLIENT_SECRET come from Google Cloud.
def get_setting(key, default=''):
    con = db()
    try:
        r = con.execute('select value from app_settings where key=?', (key,)).fetchone()
    finally:
        con.close()
    return r[0] if r else default


def set_setting(key, value):
    con = db()
    try:
        con.execute('insert into app_settings(key,value) values(?,?) on conflict(key) do update set value=excluded.value', (key, value))
        con.commit()
    finally:
        con.close()


mailer.refresh_token_provider = lambda: get_setting('gmail_refresh_token')


def _gmail_redirect_uri(request):
    return (public_url() or str(request.base_url).rstrip('/')) + '/api/gmail/callback'


@app.post('/api/admin/gmail/connect-url')
def gmail_connect_url(user=Depends(auth)):
    role_ok(user, ['super_admin'])
    missing = [k for k in ('GMAIL_CLIENT_ID', 'GMAIL_CLIENT_SECRET') if not (os.getenv(k) or '').strip()]
    if missing:
        raise HTTPException(400, f"Missing: {', '.join(missing)}. Env files found: {', '.join(mailer.ENV_FILES_FOUND) or 'NONE'} (they must be next to app.py). Save the file and restart the app.")
    return {'url': '/api/gmail/start?s=' + token({'purpose': 'gmail-start', 'uid': user['id'], 'exp': (datetime.now() + timedelta(minutes=5)).timestamp()})}


@app.get('/api/gmail/start')
def gmail_start(request: Request, s: str = ''):
    p = decode_token(s)
    if not p or p.get('purpose') != 'gmail-start':
        raise HTTPException(401, 'This link expired. Press "Connect Gmail" again.')
    state = token({'purpose': 'gmail-state', 'uid': p['uid'], 'n': secrets.token_hex(8), 'exp': (datetime.now() + timedelta(minutes=10)).timestamp()})
    return RedirectResponse(gmail_oauth_url(_gmail_redirect_uri(request), state, os.getenv('GMAIL_SENDER', '')))


@app.get('/api/gmail/callback', response_class=HTMLResponse)
def gmail_callback(request: Request, code: str = '', state: str = '', error: str = ''):
    def page(title, msg, ok):
        return HTMLResponse(f'<body style="font-family:Arial;background:#06101d;color:#fff;display:grid;place-items:center;height:100vh"><div style="max-width:520px;text-align:center">'
                            f'<h1>{"✅" if ok else "⚠"} {html.escape(title)}</h1><p>{html.escape(msg)}</p><a style="color:#38bdf8" href="/">Back to COMPESA</a></div></body>')
    st = decode_token(state)
    if not st or st.get('purpose') != 'gmail-state':
        return page('Invalid or expired request', 'Start again from Communication Center → Connect Gmail.', False)
    if error or not code:
        return page('Gmail was not connected', error or 'No authorization code received.', False)
    try:
        rt = gmail_exchange_code(code, _gmail_redirect_uri(request))
    except MailError as ex:
        return page('Gmail was not connected', str(ex), False)
    if not rt and not get_setting('gmail_refresh_token'):
        return page('No refresh token received', 'Remove COMPESA at myaccount.google.com/permissions and connect again.', False)
    if rt: set_setting('gmail_refresh_token', rt)
    con = db(); con.execute('insert into audit_logs(user_id,action,target,detail,created_at) values(?,?,?,?,?)', (st['uid'], 'CONNECT_GMAIL', '', 'Gmail API connected', now())); con.commit(); con.close()
    _outbox_wake.set()
    return page('Gmail connected', 'COMPESA can now send e-mails over HTTPS. Pending mails will be delivered shortly.', True)


# ----------------------------------------------------------------------------- public (signed) links used by the e-mail buttons
def _pub_sig(reg_code, qr_token):
    return hmac.new(SECRET, f'pub|{reg_code}|{qr_token}'.encode(), hashlib.sha256).hexdigest()[:40]


def _links_for(reg_code, qr_token, event):
    links = {'calendar': calendar_url(event, reg_code)}
    base = public_url()
    if base:
        sig = _pub_sig(reg_code, qr_token)
        links['download_qr'] = f'{base}/api/public/qr/{reg_code}.png?t={sig}&download=1'
        links['print'] = f'{base}/api/public/confirmation/{reg_code}?t={sig}&print=1'
    return links


def _public_registration(reg_code, t):
    con = db()
    try:
        r = con.execute('select r.*,e.name event_name,e.category,e.date,e.start_time,e.end_time,e.venue,u.name student_name,u.email student_email '
                        'from registrations r join events e on e.id=r.event_id join users u on u.id=r.user_id where r.reg_code=?', (reg_code,)).fetchone()
    finally:
        con.close()
    if not r or not hmac.compare_digest(_pub_sig(r['reg_code'], r['qr_token']).encode(), (t or '').encode()):
        raise HTTPException(404, 'Link not found')
    if r['status'] not in ('APPROVED', 'COMPLETED'):
        raise HTTPException(400, 'QR becomes active after approval')
    return r


@app.get('/api/public/qr/{reg_code}.png')
def public_qr(reg_code: str, t: str = '', download: int = 0):
    r = _public_registration(reg_code, t)
    headers = {'Cache-Control': 'private, no-store'}
    if download: headers['Content-Disposition'] = f'attachment; filename="qr-{reg_code}.png"'
    return Response(content=qr_png_bytes(r['reg_code'], r['qr_token']), media_type='image/png', headers=headers)


@app.get('/api/public/confirmation/{reg_code}', response_class=HTMLResponse)
def public_confirmation(reg_code: str, t: str = '', print: int = 0):
    r = _public_registration(reg_code, t)
    event = {'name': r['event_name'], 'category': r['category'], 'date': r['date'], 'start_time': r['start_time'], 'end_time': r['end_time'], 'venue': r['venue']}
    links = _links_for(r['reg_code'], r['qr_token'], event)
    links['download_qr'] = f"/api/public/qr/{r['reg_code']}.png?t={_pub_sig(r['reg_code'], r['qr_token'])}&download=1"
    return HTMLResponse(confirmation_page({'name': r['student_name']}, event, r['reg_code'], r['qr_token'], links, auto_print=bool(print)))


@app.get('/api/health')
def health():
    """Safe-to-expose status page: is the database durable, is e-mail configured, is anything stuck."""
    con = db()
    try:
        users = con.execute('select count(*) from users').fetchone()[0]
        pend = con.execute("select count(*) from email_outbox where status='PENDING'").fetchone()[0]
        failed = con.execute("select count(*) from email_outbox where status='FAILED'").fetchone()[0]
    finally:
        con.close()
    return {'ok': True, 'users': users, 'gmail_connected': gmail_api_configured(), 'config_check': {'env_files_found': mailer.ENV_FILES_FOUND, 'GMAIL_CLIENT_ID': bool((os.getenv('GMAIL_CLIENT_ID') or '').strip()), 'GMAIL_CLIENT_SECRET': bool((os.getenv('GMAIL_CLIENT_SECRET') or '').strip()), 'GMAIL_SENDER': bool((os.getenv('GMAIL_SENDER') or '').strip())}, 'persistence': persist.status(), 'email': {'transports': transports(), 'pending': pend, 'failed': failed}}


@app.post('/api/communication/retry-failed')
def retry_failed_emails(user=Depends(auth)):
    role_ok(user, ['super_admin', 'event_admin', 'event_coordinator'])
    con = db()
    try:
        cur = con.execute("update email_outbox set status='PENDING',attempts=0,next_attempt_at=? where status='FAILED'", (now(),))
        n = cur.rowcount
        con.execute("update email_logs set status='QUEUED',error='' where id in (select log_id from email_outbox where status='PENDING')")
        con.commit()
    finally:
        con.close()
    _outbox_wake.set()
    audit(user, 'RETRY_FAILED_EMAILS', '', f'{n} e-mail(s) queued again')
    return {'requeued': n}


@app.patch('/api/registrations/{rid}')
def reg_status(rid:int,x:StatusIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); status=x.status.upper()
    if status not in ['PENDING','APPROVED','REJECTED','WAITLISTED','COMPLETED']: raise HTTPException(400,'Invalid status')
    con=db(); r=con.execute('select r.*,e.name event_name,e.category,e.date,e.start_time,e.end_time,e.venue,e.max_participants,u.email student_email,u.notification_email,u.name student_name from registrations r join events e on e.id=r.event_id join users u on u.id=r.user_id where r.id=?',(rid,)).fetchone()
    if not r: con.close(); raise HTTPException(404,'Registration not found')
    if status=='APPROVED' and r['status']=='APPROVED': con.close(); return {'message':'Already approved','email_status':'already_sent'}
    con.execute('update registrations set status=?,approved_at=? where id=?',(status,now() if status=='APPROVED' else None,rid)); con.commit(); con.close()
    email_status='not_applicable'; email_error=''
    if status=='APPROVED':
        notify(r['user_id'],'Registration Approved',f"Your registration for {r['event_name']} is approved. Your QR is now active.",'REGISTRATION_APPROVED')
        user_record={'id':r['user_id'],'email':r['student_email'],'notification_email':r['notification_email'],'name':r['student_name']}
        event_record={k:r[k] for k in ['event_name','category','date','start_time','end_time','venue']}; event_record['name']=event_record.pop('event_name')
        to=(r['notification_email'] or r['student_email'] or '').strip()
        if not mail_configured(): email_status='not_configured'
        elif not is_deliverable(to): email_status='failed'; email_error='This student has no deliverable e-mail address.'
        else:
            # Queued in the database (survives restarts) and retried automatically if the mail server hiccups.
            enqueue_email('approval',r['user_id'],to,{'user':user_record,'event':event_record,'reg_code':r['reg_code'],'qr_token':r['qr_token'],
                          'links':_links_for(r['reg_code'],r['qr_token'],event_record)},registration_id=rid,
                          subject=f"✅ Registration Approved — {event_record['name']}")
            email_status='queued'
    elif status=='REJECTED': notify(r['user_id'],'Registration Update',f"Your registration for {r['event_name']} was rejected.",'REGISTRATION_REJECTED')
    audit(user,'UPDATE_REGISTRATION',str(rid),f'{status}; email={email_status}')
    return {'message':'Updated','email_status':email_status,'email_error':email_error}

@app.get('/api/communication/status')
def communication_status(user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); rows=con.execute('select status,count(*) count from email_logs group by status').fetchall(); recent=con.execute('select e.*,u.name student_name from email_logs e join users u on u.id=e.user_id order by e.created_at desc limit 30').fetchall(); con.close(); return {'configured':mail_configured(),'transport_label':' + '.join({'gmail_api':'GMAIL API','smtp':'SMTP'}[t] for t in transports()) or 'E-MAIL','stats':[dict(r) for r in rows],'recent':[dict(r) for r in recent]}

@app.get('/api/profile')
def profile(user=Depends(auth)): return public_user(user)

@app.put('/api/profile')
def update_profile(x:ProfileIn,user=Depends(auth)):
    if user['role']=='student' and x.notification_email:
        if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+',x.notification_email): raise HTTPException(400,'Invalid notification email')
    con=db(); con.execute('update users set name=?,prn=?,department=?,year=?,division=?,phone=?,skills=?,interests=?,privacy=?,notification_email=? where id=?',
                          (x.name,x.prn,x.department,x.year,x.division,x.phone,x.skills,x.interests,x.privacy,x.notification_email or user['notification_email'],user['id'])); con.commit(); con.close(); return {'message':'Profile updated'}

@app.get('/api/students')
def students(q:str='',department:str='',year:str='',division:str='',user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); rows=con.execute("select id,name,email,notification_email,prn,department,year,division,phone,points,created_at from users where role='student' and name like ? and department like ? and year like ? and division like ? order by name",(f'%{q}%',f'%{department}%',f'%{year}%',f'%{division}%')).fetchall(); con.close(); return [dict(r) for r in rows]

@app.get('/api/notifications')
def notifications(user=Depends(auth)):
    con=db(); rows=con.execute('select * from notifications where user_id=? order by created_at desc limit 100',(user['id'],)).fetchall(); con.close(); return [dict(r) for r in rows]

@app.patch('/api/notifications/{nid}/read')
def read_notification(nid:int,user=Depends(auth)):
    con=db(); con.execute('update notifications set read=1 where id=? and user_id=?',(nid,user['id'])); con.commit(); con.close(); return {'ok':True}

@app.get('/api/ai/recommendations')
def recommendations(user=Depends(auth)):
    skills=set(x.strip().lower() for x in (user['skills'] or '').split(',') if x.strip()); interests=set(x.strip().lower() for x in (user['interests'] or '').split(',') if x.strip())
    con=db(); events=con.execute('select * from events where date>=date(\'now\') order by date').fetchall(); out=[]
    for e in events:
        words=set(re.findall(r'[a-zA-Z0-9]+',((e['name']+' '+e['category']+' '+e['description']).lower()))); sm=len(skills & words)/max(1,len(skills)); im=len(interests & words)/max(1,len(interests)); dept=1 if user['department'].lower() in e['description'].lower() else 0; score=round(min(99,40*sm+40*im+20*dept),1)
        out.append({'event':{k:e[k] for k in e.keys() if k not in ('max_participants','team_size')},'match':score,'breakdown':{'skills':round(sm*100),'interests':round(im*100),'department':dept*100}})
    con.close(); return sorted(out,key=lambda x:x['match'],reverse=True)

@app.post('/api/teams')
def create_team(x:TeamIn,user=Depends(auth)):
    role_ok(user,['student']); con=db(); e=con.execute('select * from events where id=?',(x.event_id,)).fetchone()
    if not e or e['team_size']<2: con.close(); raise HTTPException(400,'Team registration not enabled')
    code='TEAM-'+secrets.token_hex(3).upper(); tcur=con.execute('insert into teams(event_id,name,invite_code,leader_id,created_at) values(?,?,?,?,?)',(x.event_id,x.name,code,user['id'],now())); tid=tcur.lastrowid; con.execute('insert into team_members(team_id,user_id,role) values(?,?,?)',(tid,user['id'],'leader')); con.commit(); con.close(); return {'team_id':tid,'invite_code':code}

@app.post('/api/teams/join')
def join_team(x:JoinTeam,user=Depends(auth)):
    role_ok(user,['student']); con=db(); t=con.execute('select * from teams where invite_code=?',(x.invite_code.strip(),)).fetchone()
    if not t: con.close(); raise HTTPException(404,'Invite code not found')
    e=con.execute('select team_size from events where id=?',(t['event_id'],)).fetchone(); count=con.execute('select count(*) from team_members where team_id=?',(t['id'],)).fetchone()[0]
    if count>=e['team_size']: con.close(); raise HTTPException(400,'Team is full')
    try: con.execute('insert into team_members(team_id,user_id,role) values(?,?,?)',(t['id'],user['id'],'member')); con.commit()
    except sqlite3.IntegrityError: con.close(); raise HTTPException(409,'Already in team')
    con.close(); return {'message':'Joined team'}

@app.get('/api/qr/{rid}.png')
def qr(rid:int, access_token:str=''):
    user=None
    if access_token:
        p=decode_token(access_token)
        if p:
            con0=db(); u0=con0.execute('select * from users where id=?',(p['uid'],)).fetchone(); con0.close(); user=dict(u0) if u0 else None
    con=db(); r=con.execute('select * from registrations where id=?',(rid,)).fetchone(); con.close()
    if not r: raise HTTPException(404,'Registration not found')
    if not user: raise HTTPException(401,'Authentication required')
    if user['role']=='student' and r['user_id']!=user['id']: raise HTTPException(403,'Forbidden')
    if r['status']!='APPROVED': raise HTTPException(400,'QR becomes active after approval')
    path=UPLOADS/f'qr_{rid}.png'; path.write_bytes(qr_png_bytes(r["reg_code"],r["qr_token"])); return FileResponse(path,media_type='image/png')

@app.post('/api/attendance/scan-image')
async def scan_image(image: UploadFile = File(...), user=Depends(auth)):
    """Decode a QR frame server-side so camera scanning works even when BarcodeDetector is unavailable."""
    role_ok(user,['super_admin','event_coordinator','volunteer'])
    if cv2 is None or np is None:
        raise HTTPException(503,'Camera QR decoder is unavailable on this server')
    data = await image.read()
    if not data or len(data) > 4 * 1024 * 1024:
        raise HTTPException(400,'Invalid camera frame')
    arr = np.frombuffer(data, dtype=np.uint8)
    frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if frame is None:
        raise HTTPException(400,'Could not read camera frame')
    detector = cv2.QRCodeDetector()
    value, points, _ = detector.detectAndDecode(frame)
    if not value:
        raise HTTPException(422,'No QR code detected')
    m = re.search(r'TOKEN:([^|\s]+)', value)
    qr_token = m.group(1) if m else value.strip()
    con=db(); r=con.execute('select * from registrations where qr_token=?',(qr_token,)).fetchone()
    if not r: con.close(); raise HTTPException(404,'Invalid QR token')
    if r['status']!='APPROVED': con.close(); raise HTTPException(400,'Registration is not approved')
    try:
        con.execute('insert into attendance(event_id,user_id,scanned_at,method) values(?,?,?,?)',(r['event_id'],r['user_id'],now(),'CAMERA_QR')); con.commit()
    except sqlite3.IntegrityError:
        con.close(); return {'message':'Already marked','student':r['user_id']}
    con.close(); notify(r['user_id'],'Attendance marked','Your event attendance was recorded successfully.','ATTENDANCE')
    return {'message':'Attendance marked','student':r['user_id']}

@app.post('/api/attendance/scan')
def scan(qr_token:str,user=Depends(auth)):
    role_ok(user,['super_admin','event_coordinator','volunteer']); con=db(); r=con.execute('select * from registrations where qr_token=?',(qr_token,)).fetchone()
    if not r: con.close(); raise HTTPException(404,'Invalid QR token')
    if r['status']!='APPROVED': con.close(); raise HTTPException(400,'Registration is not approved')
    try: con.execute('insert into attendance(event_id,user_id,scanned_at,method) values(?,?,?,?)',(r['event_id'],r['user_id'],now(),'QR')); con.commit()
    except sqlite3.IntegrityError: con.close(); return {'message':'Already marked'}
    con.close(); notify(r['user_id'],'Attendance marked','Your event attendance was recorded successfully.','ATTENDANCE'); return {'message':'Attendance marked'}

@app.get('/api/certificates')
def certs(user=Depends(auth)):
    con=db()
    if user['role']=='student': rows=con.execute('select c.*,u.name,e.name event_name from certificates c join users u on u.id=c.user_id join events e on e.id=c.event_id where c.user_id=? order by issued_at desc',(user['id'],)).fetchall()
    else: rows=con.execute('select c.*,u.name,e.name event_name from certificates c join users u on u.id=c.user_id join events e on e.id=c.event_id order by issued_at desc').fetchall()
    con.close(); return [dict(r) for r in rows]

def cert_hash(cert_id,user_id,event_id,issued): return hashlib.sha256(f'{cert_id}|{user_id}|{event_id}|{issued}'.encode()).hexdigest()

@app.post('/api/certificates/generate/{event_id}/{user_id}')
def gen_cert(event_id:int,user_id:int,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); e=con.execute('select * from events where id=?',(event_id,)).fetchone(); u=con.execute('select * from users where id=?',(user_id,)).fetchone()
    if not e or not u: con.close(); raise HTTPException(404,'Not found')
    issued=now(); cid=f'CERT-CMP-{datetime.now().year}-{secrets.token_hex(3).upper()}'; h=cert_hash(cid,user_id,event_id,issued)
    con.execute('insert into certificates(cert_id,user_id,event_id,issued_at,hash,source) values(?,?,?,?,?,?)',(cid,user_id,event_id,issued,h,'generated')); con.commit(); con.close()
    notify(user_id,'Certificate available',f'Your certificate for {e["name"]} is ready. ID: {cid}','CERTIFICATE'); return {'certificate_id':cid}

@app.post('/api/certificates/upload')
async def upload_certificate(event_id:int=Form(...), user_id:int=Form(...), certificate:UploadFile=File(...), user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); e=con.execute('select * from events where id=?',(event_id,)).fetchone(); u=con.execute('select * from users where id=?',(user_id,)).fetchone(); con.close()
    if not e or not u: raise HTTPException(404,'Student or event not found')
    data=await certificate.read()
    if len(data)>10*1024*1024: raise HTTPException(413,'Certificate file is too large')
    ext=Path(certificate.filename or '').suffix.lower() or '.pdf'
    if ext not in ['.pdf','.png','.jpg','.jpeg']: raise HTTPException(400,'Only PDF/JPG/PNG certificates are allowed')
    cid=f'CERT-CMP-{datetime.now().year}-{secrets.token_hex(3).upper()}'; issued=now(); h=cert_hash(cid,user_id,event_id,issued); path=UPLOADS/f'{cid}{ext}'; path.write_bytes(data)
    con=db(); con.execute('insert into certificates(cert_id,user_id,event_id,issued_at,hash,source,file_path) values(?,?,?,?,?,?,?)',(cid,user_id,event_id,issued,h,'uploaded',str(path.name))); con.commit(); con.close(); notify(user_id,'Certificate available',f'Your uploaded certificate for {e["name"]} is available. ID: {cid}','CERTIFICATE'); audit(user,'UPLOAD_CERTIFICATE',cid,u['name']); return {'certificate_id':cid,'file':f'/uploads/{path.name}'}

@app.get('/api/certificates/verify/{cid}')
def verify(cid:str):
    con=db(); r=con.execute('select c.*,u.name,u.prn,e.name event_name,e.date from certificates c join users u on u.id=c.user_id join events e on e.id=c.event_id where c.cert_id=?',(cid,)).fetchone(); con.close()
    if not r: return {'valid':False}
    valid=hmac.compare_digest(r['hash'],cert_hash(r['cert_id'],r['user_id'],r['event_id'],r['issued_at'])); return {'valid':valid,**dict(r)}

@app.get('/api/certificates/{cid}/pdf')
def cert_pdf(cid:str):
    con=db(); r=con.execute('select c.*,u.name,u.prn,u.department,e.name event_name,e.date from certificates c join users u on u.id=c.user_id join events e on e.id=c.event_id where c.cert_id=?',(cid,)).fetchone(); con.close()
    if not r: raise HTTPException(404,'Certificate not found')
    if r['file_path'] and Path(UPLOADS/r['file_path']).exists(): return FileResponse(UPLOADS/r['file_path'],media_type='application/pdf' if r['file_path'].endswith('.pdf') else 'image/*',filename=r['file_path'])
    path=UPLOADS/f'{cid}.pdf'; c=canvas.Canvas(str(path),pagesize=landscape(A4)); w,h=A4[1],A4[0]
    c.setFillColorRGB(0.03,0.07,0.12); c.rect(0,0,w,h,fill=1,stroke=0); c.setFillColorRGB(0.2,0.65,1); c.rect(35,35,w-70,h-70,fill=0,stroke=1)
    logo=ASSETS/'brand.png'
    if logo.exists(): c.drawImage(str(logo),55,h-95,width=260,height=54,preserveAspectRatio=True,mask='auto')
    c.setFillColorRGB(1,1,1); c.setFont('Helvetica-Bold',30); c.drawCentredString(w/2,h-170,'CERTIFICATE OF PARTICIPATION')
    c.setFont('Helvetica',14); c.drawCentredString(w/2,h-215,'This certifies that')
    c.setFont('Helvetica-Bold',27); c.drawCentredString(w/2,h-260,r['name'])
    c.setFont('Helvetica',13); c.drawCentredString(w/2,h-295,f'PRN: {r["prn"] or "—"}  •  {r["department"] or "Computer Engineering"}')
    c.drawCentredString(w/2,h-335,f'participated in {r["event_name"]}')
    c.setFont('Helvetica',11); c.drawCentredString(w/2,75,f'Certificate ID: {r["cert_id"]}  •  Issued: {r["issued_at"][:10]}  •  Verify at COMPESA portal')
    c.save(); return FileResponse(path,media_type='application/pdf',filename=f'{cid}.pdf')

@app.post('/api/feedback/{event_id}')
def feedback(event_id:int,x:FeedbackIn,user=Depends(auth)):
    if not 1<=x.rating<=5: raise HTTPException(400,'Rating must be 1-5')
    con=db(); con.execute('insert or replace into feedback(event_id,user_id,content,rating,created_at) values(?,?,?,?,?)',(event_id,user['id'],x.content,x.rating,now())); con.commit(); con.close(); return {'message':'Feedback saved'}

@app.get('/api/leaderboard')
def leaderboard(user=Depends(auth)):
    con=db(); rows=con.execute("select name,prn,points,department from users where role='student' order by points desc,name limit 50").fetchall(); con.close(); return [dict(r) for r in rows]

@app.post('/api/results')
def result(x:ResultIn,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); con.execute('insert into results(event_id,user_id,position,score,mention) values(?,?,?,?,?)',(x.event_id,x.user_id,x.position,x.score,x.mention)); pts={'Winner':50,'1st Runner Up':30,'2nd Runner Up':20}.get(x.position,10); con.execute('update users set points=points+? where id=?',(pts,x.user_id)); con.commit(); con.close(); notify(x.user_id,'Result published',f'You achieved {x.position} in the event.','RESULT'); return {'message':'Result published'}

@app.get('/api/results/me')
def my_results(user=Depends(auth)):
    con=db(); rows=con.execute('select r.*,e.name event_name,e.date from results r join events e on e.id=r.event_id where r.user_id=? order by e.date desc',(user['id'],)).fetchall(); con.close(); return [dict(r) for r in rows]

@app.get('/api/venues')
def venues(user=Depends(auth)):
    con=db(); rows=con.execute('select * from venues order by capacity').fetchall(); con.close(); return [dict(r) for r in rows]

class QRActiveIn(BaseModel): active: bool

class PrefsIn(BaseModel):
    categories: dict = {}
    channels: dict = {}

QR_MAX_BYTES = 5 * 1024 * 1024
PAYMENT_ADMIN_ROLES = ['super_admin','event_admin','event_coordinator']


def _qr_row(r, admin=False):
    d={'id':r['id'],'label':r['label'],'upi_id':r['upi_id'] or '','image_path':r['image_path'],'active':bool(r['active'])}
    if admin: d['created_at']=r['created_at']
    return d


def _remove_qr_file(path):
    # Only files we saved under /uploads are ever deleted; the bundled default stays on disk.
    if path and str(path).startswith('/uploads/'):
        try:
            target=UPLOADS/Path(str(path)).name
            if target.is_file(): target.unlink()
        except Exception: pass


@app.get('/api/payment-qrs')
def list_payment_qrs(user=Depends(auth)):
    """Students get only the active QR codes; admins get every QR (active or not)."""
    admin = user['role'] in PAYMENT_ADMIN_ROLES
    con=db(); rows=con.execute('select * from payment_qrs'+('' if admin else ' where active=1')+' order by id desc').fetchall(); con.close()
    return [_qr_row(r,admin) for r in rows]


@app.post('/api/payment-qrs')
async def add_payment_qr(label:str=Form(...), upi_id:str=Form(''), image:UploadFile=File(...), user=Depends(auth)):
    role_ok(user,PAYMENT_ADMIN_ROLES)
    label=label.strip()
    if not label: raise HTTPException(400,'Give the QR a name (e.g. "Main UPI - Anis")')
    if len(label)>80: raise HTTPException(400,'QR name is too long')
    if image.content_type not in {'image/jpeg','image/png','image/webp'}: raise HTTPException(400,'Upload the payment QR as a JPG, PNG or WEBP image')
    data=await image.read()
    if not data: raise HTTPException(400,'The uploaded image is empty')
    if len(data)>QR_MAX_BYTES: raise HTTPException(400,'QR image must be 5 MB or smaller')
    ext={'image/jpeg':'.jpg','image/png':'.png','image/webp':'.webp'}[image.content_type]
    name=f'payment_qr_{uuid.uuid4().hex}{ext}'; (UPLOADS/name).write_bytes(data)
    con=db(); cur=con.execute('insert into payment_qrs(label,upi_id,image_path,active,created_by,created_at) values(?,?,?,?,?,?)',(label,upi_id.strip()[:120],f'/uploads/{name}',1,user['id'],now()))
    qid=cur.lastrowid; con.commit(); con.close()
    audit(user,'ADD_PAYMENT_QR',str(qid),label)
    return {'id':qid,'message':'Payment QR added'}


@app.patch('/api/payment-qrs/{qid}')
def toggle_payment_qr(qid:int,x:QRActiveIn,user=Depends(auth)):
    role_ok(user,PAYMENT_ADMIN_ROLES); con=db()
    r=con.execute('select * from payment_qrs where id=?',(qid,)).fetchone()
    if not r: con.close(); raise HTTPException(404,'Payment QR not found')
    con.execute('update payment_qrs set active=? where id=?',(int(x.active),qid)); con.commit(); con.close()
    audit(user,'TOGGLE_PAYMENT_QR',str(qid),f'{r["label"]}: {"active" if x.active else "hidden"}')
    return {'message':'Payment QR is now '+('visible to students' if x.active else 'hidden from students')}


@app.delete('/api/payment-qrs/{qid}')
def delete_payment_qr(qid:int,user=Depends(auth)):
    role_ok(user,PAYMENT_ADMIN_ROLES); con=db()
    r=con.execute('select * from payment_qrs where id=?',(qid,)).fetchone()
    if not r: con.close(); raise HTTPException(404,'Payment QR not found')
    # Old registrations keep their payment record; they just stop pointing at this QR.
    con.execute('update registrations set payment_qr_id=null where payment_qr_id=?',(qid,))
    con.execute('delete from payment_qrs where id=?',(qid,)); con.commit(); con.close()
    _remove_qr_file(r['image_path']); audit(user,'DELETE_PAYMENT_QR',str(qid),r['label'])
    return {'message':'Payment QR removed'}


DEFAULT_PREFS={'categories':{'coding':True,'hackathon':True,'workshop':True,'gaming':False},'channels':{'portal':True,'gmail':True,'sms':False}}


@app.get('/api/preferences')
def get_prefs(user=Depends(auth)):
    try: saved=json.loads(user.get('notification_prefs') or '{}')
    except Exception: saved={}
    return {k:{**DEFAULT_PREFS[k],**{a:bool(b) for a,b in (saved.get(k) or {}).items() if a in DEFAULT_PREFS[k]}} for k in DEFAULT_PREFS}


@app.put('/api/preferences')
def save_prefs(x:PrefsIn,user=Depends(auth)):
    clean={k:{a:bool(getattr(x,k).get(a,DEFAULT_PREFS[k][a])) for a in DEFAULT_PREFS[k]} for k in DEFAULT_PREFS}
    con=db(); con.execute('update users set notification_prefs=? where id=?',(json.dumps(clean),user['id'])); con.commit(); con.close()
    return {'message':'Notification preferences saved','preferences':clean}


@app.get('/api/reports/registrations.csv')
def reg_report(user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); rows=con.execute('select r.reg_code,u.name,u.email,u.notification_email,u.prn,u.department,u.year,u.division,e.name event_name,e.category,e.date,r.status,r.payment_mode,r.payment_status,r.payment_reference,r.reference_person,r.created_at from registrations r join users u on u.id=r.user_id join events e on e.id=r.event_id order by r.created_at desc').fetchall(); con.close(); out=io.StringIO(); w=csv.writer(out); w.writerow(rows[0].keys() if rows else ['No data']); [w.writerow(list(r)) for r in rows]; return StreamingResponse(iter([out.getvalue()]),media_type='text/csv',headers={'Content-Disposition':'attachment; filename=compesa_registrations.csv'})

@app.get('/api/reports/attendance.csv')
def attendance_report(user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); rows=con.execute("select u.name,u.prn,u.department,u.year,u.division,u.phone,u.email,u.notification_email,e.name event_name,r.reg_code,r.status registration_status,a.scanned_at check_in_time,a.method qr_verification from attendance a join users u on u.id=a.user_id join events e on e.id=a.event_id left join registrations r on r.user_id=a.user_id and r.event_id=a.event_id order by a.scanned_at desc").fetchall(); con.close(); out=io.StringIO(); w=csv.writer(out); w.writerow(rows[0].keys() if rows else ['No data']); [w.writerow(list(r)) for r in rows]; return StreamingResponse(iter([out.getvalue()]),media_type='text/csv',headers={'Content-Disposition':'attachment; filename=compesa_attended_students.csv'})

@app.get('/api/reports/participants.csv')
def participants_report(user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); rows=con.execute("select u.name,u.prn,u.department,u.year,u.division,u.phone,u.email,u.notification_email,e.name event_name,e.category,r.reg_code,r.status registration_status,r.created_at registration_date,a.scanned_at check_in_time,case when a.id is not null then 'ATTENDED' else 'NOT_ATTENDED' end attendance_status,r.payment_mode,r.payment_status,r.payment_reference,r.reference_person from registrations r join users u on u.id=r.user_id join events e on e.id=r.event_id left join attendance a on a.user_id=r.user_id and a.event_id=r.event_id order by r.created_at desc").fetchall(); con.close(); out=io.StringIO(); w=csv.writer(out); w.writerow(rows[0].keys() if rows else ['No data']); [w.writerow(list(r)) for r in rows]; return StreamingResponse(iter([out.getvalue()]),media_type='text/csv',headers={'Content-Disposition':'attachment; filename=compesa_event_participants.csv'})

@app.get('/api/reports/students.csv')
def students_report(user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); rows=con.execute("select name,prn,department,year,division,phone,email,notification_email,skills,interests,points,created_at from users where role='student' order by name").fetchall(); con.close(); out=io.StringIO(); w=csv.writer(out); w.writerow(rows[0].keys() if rows else ['No data']); [w.writerow(list(r)) for r in rows]; return StreamingResponse(iter([out.getvalue()]),media_type='text/csv',headers={'Content-Disposition':'attachment; filename=compesa_all_students.csv'})

@app.get('/api/audit')
def audit_logs(user=Depends(auth)):
    role_ok(user,['super_admin']); con=db(); rows=con.execute('select a.*,u.name from audit_logs a join users u on u.id=a.user_id order by a.created_at desc limit 200').fetchall(); con.close(); return [dict(r) for r in rows]


@app.get('/api/admin/backup')
def download_backup(user=Depends(auth)):
    """Lets the admin download a full, consistent snapshot of the live database.
    This is the real fix for hosts with non-persistent storage (e.g. Render's free
    plan): download a backup regularly, and restore it below if the live data ever
    resets."""
    role_ok(user, ['super_admin'])
    dest = _backup('manual', keep=10)
    audit(user, 'DOWNLOAD_BACKUP', '', 'Database backup downloaded')
    return FileResponse(dest, media_type='application/octet-stream', filename=dest.name)


@app.post('/api/admin/restore')
async def restore_backup(file: UploadFile = File(...), user=Depends(auth)):
    """Replaces the live database with an uploaded backup file. The database that
    was live just before the restore is itself safety-copied first, so a restore
    can always be undone."""
    role_ok(user, ['super_admin'])
    data = await file.read()
    if len(data) > 200 * 1024 * 1024:
        raise HTTPException(413, 'Backup file is too large')
    if data[:16] != b'SQLite format 3\x00':
        raise HTTPException(400, 'This does not look like a valid SQLite database file')
    BACKUPS.mkdir(parents=True, exist_ok=True)
    tmp_path = BACKUPS / f'_incoming_{secrets.token_hex(6)}.db'
    tmp_path.write_bytes(data)
    try:
        chk = sqlite3.connect(tmp_path)
        tables = {r[0] for r in chk.execute("select name from sqlite_master where type='table'").fetchall()}
        chk.close()
        if not {'users', 'events', 'registrations'}.issubset(tables):
            raise HTTPException(400, 'This file does not look like a COMPESA database backup')
    except HTTPException:
        tmp_path.unlink(missing_ok=True); raise
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise HTTPException(400, 'Could not read this file as a SQLite database')
    _backup('pre_restore', keep=5)  # safety copy of what was live, in case this needs undoing
    shutil.move(str(tmp_path), str(DB))
    for suffix in ('-wal', '-shm'):
        stale = Path(str(DB) + suffix)
        if stale.exists():
            try: stale.unlink()
            except Exception: pass
    try:
        c2=db(); ensure_integrity(c2); c2.close()
    except Exception: logger.exception('Could not re-apply integrity guards after restore')
    audit(user, 'RESTORE_BACKUP', '', 'Database restored from an uploaded backup file')
    return {'message': 'Database restored successfully.'}


@app.post('/api/announcements')
def announcement(x:Announcement,user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db(); ids=[r[0] for r in con.execute("select id from users where role='student'").fetchall()]
    if x.event_id:
        con.execute('insert into event_announcements(event_id,title,body,created_at,created_by) values(?,?,?,?,?)',(x.event_id,x.title,x.body,now(),user['id']))
    con.commit(); con.close()
    for uid in ids: notify(uid,x.title,x.body,'ANNOUNCEMENT')
    audit(user,'ANNOUNCEMENT','EVENT' if x.event_id else 'ALL',x.title); return {'sent':len(ids)}

@app.get('/api/announcements/me')
def announcements_me(user=Depends(auth)):
    con=db(); rows=con.execute("select n.* from notifications n where n.user_id=? and n.kind='ANNOUNCEMENT' order by n.created_at desc limit 50",(user['id'],)).fetchall(); con.close(); return [dict(r) for r in rows]

@app.post('/api/communication/test')
def test_email(email:str,user=Depends(auth)):
    role_ok(user,['super_admin']);
    if not smtp_configured(): return {'sent':False,'message':'E-mail is not configured. Fill GMAIL_CLIENT_ID/GMAIL_CLIENT_SECRET (+ press Connect Gmail) or SMTP_HOST/SMTP_USER/SMTP_PASSWORD in .env, then restart the app.'}
    ok,err=send_compesa_email(email,'COMPESA Communication Test','<h2>COMPESA Email Test ✓</h2><p>Your e-mail configuration is working.</p>','COMPESA email configuration is working.',attempts=1)
    return {'sent':ok,'message':('Test email sent via '+' + '.join(transports())+'.') if ok else err}

@app.get('/api/analytics')
def analytics(user=Depends(auth)):
    role_ok(user,['super_admin','event_admin','event_coordinator']); con=db()
    ratings=con.execute('select round(avg(rating),2) avg,count(*) responses from feedback').fetchone(); active=con.execute("select u.name,count(*) c from registrations r join users u on u.id=r.user_id group by u.id order by c desc limit 10").fetchall(); attendance=con.execute('select count(*) from attendance').fetchone()[0]
    attendance_pct=con.execute("select round(100.0*sum(case when a.id is not null then 1 else 0 end)/max(1,count(*)),1) p from registrations r left join attendance a on a.user_id=r.user_id and a.event_id=r.event_id where r.status in ('APPROVED','COMPLETED')").fetchone()[0]
    categories=con.execute('select e.category,count(*) count from registrations r join events e on e.id=r.event_id group by e.category order by count desc').fetchall(); years=con.execute('select u.year,count(*) count from registrations r join users u on u.id=r.user_id group by u.year order by count desc').fetchall(); types=[{'type':'Individual','count':con.execute("select count(*) from registrations where team_id is null").fetchone()[0]},{'type':'Team','count':con.execute("select count(*) from registrations where team_id is not null").fetchone()[0]}]
    con.close(); return {'rating':dict(ratings),'attendance_records':attendance,'attendance_percent':attendance_pct,'active_students':[dict(x) for x in active],'categories':[dict(x) for x in categories],'years':[dict(x) for x in years],'registration_types':types}

@app.get('/api/problems/{event_id}')
def problems(event_id:int,user=Depends(auth)):
    con=db(); rows=con.execute('select * from problems where event_id=?',(event_id,)).fetchall(); con.close(); return [dict(r) for r in rows]

@app.post('/api/submissions')
def submission(x:SubmitIn,user=Depends(auth)):
    if len(x.code)>50000: raise HTTPException(413,'Submission too large')
    score=100 if ('return' in x.code or 'print' in x.code) else 20; status='PASSED' if score>=100 else 'REVIEW'
    con=db(); con.execute('insert into submissions(problem_id,user_id,language,code,status,score,submitted_at) values(?,?,?,?,?,?,?)',(x.problem_id,user['id'],x.language,x.code,status,score,now())); con.commit(); con.close(); return {'status':status,'score':score,'note':'Demo judge mode: arbitrary code execution is intentionally disabled for server safety.'}

@app.get('/api/public/profile/{prn}')
def public_profile(prn:str):
    con=db(); u=con.execute("select name,prn,department,year,division,skills,points,privacy from users where prn=? and coalesce(privacy,'college')!='private' order by id limit 1",(prn,)).fetchone(); con.close()
    if not u or u['privacy']=='private': raise HTTPException(404,'Profile unavailable')
    return dict(u)
