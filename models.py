from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Scan(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    target = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')  # pending, running, completed
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    vuln_count = db.Column(db.Integer, default=0)
    progress = db.Column(db.Integer, default=0)          # 0–100
    current_url = db.Column(db.String(200))

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), db.ForeignKey('scan.id'))
    type = db.Column(db.String(50))
    url = db.Column(db.String(200))
    param = db.Column(db.String(50))
    payload = db.Column(db.Text)
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
