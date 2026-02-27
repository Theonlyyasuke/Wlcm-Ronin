from datetime import datetime
from extensions import db
from passlib.hash import bcrypt

class Role:
    ADMIN = "admin"
    ORGANIZER = "organizer"
    USER = "user"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default=Role.USER)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = bcrypt.hash(password)

    def check_password(self, password):
        return bcrypt.verify(password, self.password_hash)


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    start_time = db.Column(db.String, nullable=False)
    capacity = db.Column(db.Integer, default=0)
    price_naira = db.Column(db.Integer, default=0)
    organizer_id = db.Column(db.Integer, db.ForeignKey("user.id"))


class BookingStatus:
    ACTIVE = "active"
    CANCELLED = "cancelled"


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    event_id = db.Column(db.Integer, db.ForeignKey("event.id"))
    quantity = db.Column(db.Integer, default=1)
    total_price_naira = db.Column(db.Integer)
    status = db.Column(db.String(50), default=BookingStatus.ACTIVE)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)