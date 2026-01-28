from flask import Blueprint, request, jsonify, current_app, url_for
from ..extensions import db
from ..models import User, Role
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
import datetime
from ..utils import role_required 
from itsdangerous import URLSafeTimedSerializer

bp = Blueprint("auth", __name__, url_prefix="/api/auth")

@bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    name = data.get("name")
    role = data.get("role", Role.USER)

    if not email or not password:
        return jsonify({"msg": "email and password are required"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "Email already registered"}), 400

    user = User(email=email, name=name, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "Registered", "user_id": user.id}), 201

@bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"msg": "Bad credentials"}), 401
    if not user.is_active:
        return jsonify({"msg": "Account inactive"}), 403

    access = create_access_token(identity=user.id, additional_claims={"role": user.role})
    refresh = create_refresh_token(identity=user.id)
    return jsonify({"access_token": access, "refresh_token": refresh, "user": {"id": user.id, "email": user.email, "role": user.role}}), 200

@bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    email = data.get("email")
    user = User.query.filter_by(email=email).first()
    if not user:
        # don't reveal whether email exists
        return jsonify({"msg": "If the email exists, a reset link will be sent."}), 200

    # create token (itsdangerous) -- include user id
    s = URLSafeTimedSerializer(current_app.config["RESET_PASSWORD_SECRET"])
    token = s.dumps({"user_id": user.id})
    # In production, send email with the token link
    reset_url = url_for("auth.reset_password", token=token, _external=True)
    current_app.logger.info(f"Password reset link (DEV): {reset_url}")  # replace with email send
    return jsonify({"msg": "If the email exists, a reset link will be sent."}), 200

@bp.route("/reset-password/<token>", methods=["POST"])
def reset_password(token):
    data = request.get_json()
    new_password = data.get("password")
    if not new_password:
        return jsonify({"msg": "password required"}), 400

    s = URLSafeTimedSerializer(current_app.config["RESET_PASSWORD_SECRET"])
    try:
        payload = s.loads(token, max_age=3600)  # 1 hour
    except Exception:
        return jsonify({"msg": "Invalid or expired token"}), 400

    user = User.query.get(payload.get("user_id"))
    if not user:
        return jsonify({"msg": "Invalid token"}), 400

    user.set_password(new_password)
    db.session.commit()
    return jsonify({"msg": "Password reset successful"}), 200

from flask import Blueprint, request, jsonify
from ..extensions import db
from ..models import Event, User, Role
from ..utils import role_required
from flask_jwt_extended import jwt_required, get_jwt_identity

bp = Blueprint("events", __name__, url_prefix="/api/events")

@bp.route("", methods=["GET"])
def list_events():
    # add pagination & filters
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 20)), 100)
    q = Event.query.order_by(Event.start_time.desc()).paginate(page=page, per_page=per_page, error_out=False)
    events = [{
        "id": e.id, "title": e.title, "start_time": e.start_time.isoformat(),
        "end_time": e.end_time.isoformat() if e.end_time else None,
        "organizer_id": e.organizer_id, "capacity": e.capacity, "price_naira": e.price_naira
    } for e in q.items]
    return jsonify({"events": events, "total": q.total, "page": page}), 200

@bp.route("/<int:event_id>", methods=["GET"])
def get_event(event_id):
    e = Event.query.get_or_404(event_id)
    return jsonify({
        "id": e.id, "title": e.title, "description": e.description, "location": e.location,
        "start_time": e.start_time.isoformat(), "end_time": e.end_time.isoformat() if e.end_time else None,
        "capacity": e.capacity, "price_naira": e.price_naira, "organizer_id": e.organizer_id
    }), 200

@bp.route("/create", methods=["POST"])
@jwt_required()
@role_required(Role.ORGANIZER, Role.ADMIN)
def create_event():
    data = request.get_json()
    current_user_id = get_jwt_identity()
    # Minimal validation
    required = ["title", "start_time"]
    for r in required:
        if r not in data:
            return jsonify({"msg": f"{r} required"}), 400
    e = Event(
        title=data["title"],
        description=data.get("description"),
        location=data.get("location"),
        start_time=data["start_time"],
        end_time=data.get("end_time"),
        capacity=data.get("capacity", 0),
        price_cents=int(data.get("price_naira", 0)),
        organizer_id=current_user_id
    )
    db.session.add(e)
    db.session.commit()
    return jsonify({"msg": "Created", "event_id": e.id}), 201

@bp.route("/<int:event_id>/update", methods=["PATCH"])
@jwt_required()
def update_event(event_id):
    data = request.get_json()
    e = Event.query.get_or_404(event_id)
    current_user_id = get_jwt_identity()
    # Only organizer of event or admin can update
    if e.organizer_id != current_user_id:
        # check admin
        from ..models import User
        user = User.query.get(current_user_id)
        if user.role != Role.ADMIN:
            return jsonify({"msg": "Not authorized"}), 403
    # update allowed fields
    for field in ["title", "description", "location", "start_time", "end_time", "capacity", "price_naira"]:
        if field in data:
            setattr(e, field, data[field])
    db.session.commit()
    return jsonify({"msg": "Updated"}), 200

@bp.route("/<int:event_id>/delete", methods=["DELETE"])
@jwt_required()
def delete_event(event_id):
    e = Event.query.get_or_404(event_id)
    current_user_id = get_jwt_identity()
    if e.organizer_id != current_user_id:
        from ..models import User
        user = User.query.get(current_user_id)
        if user.role != Role.ADMIN:
            return jsonify({"msg": "Not authorized"}), 403
    db.session.delete(e)
    db.session.commit()
    return jsonify({"msg": "Deleted"}), 200


from flask import Blueprint, request, jsonify
from ..extensions import db
from ..models import Booking, Event, BookingStatus
from flask_jwt_extended import jwt_required, get_jwt_identity

bp = Blueprint("bookings", __name__, url_prefix="/api/bookings")

@bp.route("", methods=["GET"])
@jwt_required()
def list_user_bookings():
    user_id = get_jwt_identity()
    bookings = Booking.query.filter_by(user_id=user_id).order_by(Booking.created_at.desc()).all()
    result = []
    for b in bookings:
        result.append({
            "id": b.id,
            "event_id": b.event_id,
            "quantity": b.quantity,
            "total_price_naira": b.total_price_naira,
            "status": b.status
        })
    return jsonify({"bookings": result}), 200

@bp.route("/<int:booking_id>", methods=["GET"])
@jwt_required()
def get_booking(booking_id):
    user_id = get_jwt_identity()
    b = Booking.query.get_or_404(booking_id)
    if b.user_id != user_id:
        return jsonify({"msg": "Not authorized"}), 403
    return jsonify({
        "id": b.id, "event_id": b.event_id, "quantity": b.quantity, "total_price_naira": b.total_price_naira, "status": b.status
    }), 200

@bp.route("/create", methods=["POST"])
@jwt_required()
def create_booking():
    data = request.get_json()
    user_id = get_jwt_identity()
    event_id = data.get("event_id")
    quantity = int(data.get("quantity", 1))
    if not event_id or quantity < 1:
        return jsonify({"msg": "event_id and quantity are required"}), 400

    event = Event.query.get_or_404(event_id)
    # capacity check (simple)
    total_booked = sum(b.quantity for b in event.tickets if b.status == BookingStatus.ACTIVE)
    if event.capacity and (total_booked + quantity) > event.capacity:
        return jsonify({"msg": "Not enough capacity"}), 400

    total_price = event.price_naira * quantity
    # Payment flow would go here (placeholder)
    booking = Booking(user_id=user_id, event_id=event_id, quantity=quantity, total_price_naira=total_price)
    db.session.add(booking)
    db.session.commit()
    return jsonify({"msg": "Booked", "booking_id": booking.id}), 201

@bp.route("/cancel/<int:booking_id>", methods=["POST"])
@jwt_required()
def cancel_booking(booking_id):
    user_id = get_jwt_identity()
    b = Booking.query.get_or_404(booking_id)
    if b.user_id != user_id:
        return jsonify({"msg": "Not authorized"}), 403
    if b.status == BookingStatus.CANCELLED:
        return jsonify({"msg": "Already cancelled"}), 400
    b.status = BookingStatus.CANCELLED
    db.session.commit()
    # Optionally refund (placeholder)
    return jsonify({"msg": "Cancelled"}), 200


from flask import Blueprint, jsonify, request
from ..extensions import db
from ..models import User
from ..utils import role_required
from flask_jwt_extended import jwt_required

bp = Blueprint("admin", __name__, url_prefix="/api/users")

@bp.route("", methods=["GET"])
@jwt_required()
@role_required("admin")
def list_users():
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 20)), 100)
    q = User.query.paginate(page=page, per_page=per_page, error_out=False)
    users = [{"id": u.id, "email": u.email, "role": u.role, "is_active": u.is_active} for u in q.items]
    return jsonify({"users": users, "total": q.total}), 200

@bp.route("/<int:user_id>", methods=["GET"])
@jwt_required()
@role_required("admin")
def get_user(user_id):
    u = User.query.get_or_404(user_id)
    return jsonify({"id": u.id, "email": u.email, "role": u.role, "is_active": u.is_active}), 200

@bp.route("/<int:user_id>/deactivate", methods=["POST"])
@jwt_required()
@role_required("admin")
def deactivate_user(user_id):
    u = User.query.get_or_404(user_id)
    u.is_active = False
    db.session.commit()
    return jsonify({"msg": "User deactivated"}), 200

