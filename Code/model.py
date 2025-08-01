from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
# Initialize db as a global instance of SQLAlchemy
db = SQLAlchemy()

# User model
class User(db.Model):
    __tablename__ = "user"
    uid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    fname = db.Column(db.String, nullable=False)
    lname = db.Column(db.String, nullable=True)
    is_blocked = db.Column(db.Boolean, default=False)  # Add this line for block/unblock functionality


# Admin model
class Admin(db.Model):
    __tablename__ = "admin"
    aid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

# Services model
class Services(db.Model):
    __tablename__ = "services"
    sid = db.Column(db.Integer, primary_key=True)
    sname = db.Column(db.String, unique=True, nullable=False)
    base_price = db.Column(db.Float, nullable=False)

# Professional model
class AppliedProfessional(db.Model):
    __tablename__ = "applied_professional"
    id = db.Column(db.Integer, primary_key=True)  # Auto-generated primary key
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    fname = db.Column(db.String(80), nullable=False)
    lname = db.Column(db.String(80), nullable=True)
    service = db.Column(db.String(100), nullable=False)
    qualifications = db.Column(db.String(500), nullable=True)

class Professional(db.Model):
    __tablename__ = "professional"
    pid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)  # Ensure this column exists
    password = db.Column(db.String(200), nullable=False)
    fname = db.Column(db.String(80), nullable=False)
    lname = db.Column(db.String(80), nullable=True)
    service = db.Column(db.String(100), nullable=False)
    qualifications = db.Column(db.String(500), nullable=True)
    blocked = db.Column(db.Boolean, default=False)  # Block status, defaults to False (not blocked)
class ServiceRequest(db.Model):
    __tablename__ = 'service_requests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.uid'), nullable=False)  # User who made the request
    service_id = db.Column(db.Integer, db.ForeignKey('services.sid'), nullable=False)  # Service being requested
    status = db.Column(db.String(20), default='Pending')  # Status of the request (e.g., Pending, Completed)
    request_date = db.Column(db.DateTime, default=datetime.utcnow)  # Date of request
    user = db.relationship('User', backref=db.backref('requests', lazy=True))
    closed_date = db.Column(db.DateTime, nullable=True)  # New field for closed date
    professional_review = db.Column(db.Text, nullable=True)  # Professional's review
    service = db.relationship('Services', backref=db.backref('requests', lazy=True))
    user_review = db.Column(db.Text, nullable=True)  # Professional's review
    professional_review = db.Column(db.Text, nullable=True)  # Professional's review

