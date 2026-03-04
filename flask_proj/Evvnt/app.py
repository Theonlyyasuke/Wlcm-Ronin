from flask import Flask, jsonify, request, url_for, current_app
from .extensions import db, migrate, jwt
from .models import User, Role, Event, Booking, BookingStatus
from .utils import role_required
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from itsdangerous import URLSafeTimedSerializer
from .config import Config
from flask import Blueprint

# ----------------------------
# AUTH BLUEPRINT
# ----------------------------
auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

@auth_bp.route("/register", methods=["POST"])
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

@auth_bp.route("/login", methods=["POST"])
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

@auth_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    email = data.get("email")
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"msg": "If the email exists, a reset link will be sent."}), 200

    s = URLSafeTimedSerializer(current_app.config["RESET_PASSWORD_SECRET"])
    token = s.dumps({"user_id": user.id})
    reset_url = url_for("auth.reset_password", token=token, _external=True)
    current_app.logger.info(f"Password reset link (DEV): {reset_url}")
    return jsonify({"msg": "If the email exists, a reset link will be sent."}), 200

@auth_bp.route("/reset-password/<token>", methods=["POST"])
def reset_password(token):
    data = request.get_json()
    new_password = data.get("password")
    if not new_password:
        return jsonify({"msg": "password required"}), 400

    s = URLSafeTimedSerializer(current_app.config["RESET_PASSWORD_SECRET"])
    try:
        payload = s.loads(token, max_age=3600)
    except Exception:
        return jsonify({"msg": "Invalid or expired token"}), 400

    user = User.query.get(payload.get("user_id"))
    if not user:
        return jsonify({"msg": "Invalid token"}), 400

    user.set_password(new_password)
    db.session.commit()
    return jsonify({"msg": "Password reset successful"}), 200

# ----------------------------
# EVENTS BLUEPRINT
# ----------------------------
events_bp = Blueprint("events", __name__, url_prefix="/api/events")

@events_bp.route("", methods=["GET"])
def list_events():
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 20)), 100)
    q = Event.query.order_by(Event.start_time.desc()).paginate(page=page, per_page=per_page, error_out=False)
    events = [{
        "id": e.id, "title": e.title, "start_time": e.start_time.isoformat(),
        "end_time": e.end_time.isoformat() if e.end_time else None,
        "organizer_id": e.organizer_id, "capacity": e.capacity, "price_naira": e.price_naira
    } for e in q.items]
    return jsonify({"events": events, "total": q.total, "page": page}), 200

@events_bp.route("/<int:event_id>", methods=["GET"])
def get_event(event_id):
    e = Event.query.get_or_404(event_id)
    return jsonify({
        "id": e.id, "title": e.title, "description": e.description, "location": e.location,
        "start_time": e.start_time.isoformat(), "end_time": e.end_time.isoformat() if e.end_time else None,
        "capacity": e.capacity, "price_naira": e.price_naira, "organizer_id": e.organizer_id
    }), 200

@events_bp.route("/create", methods=["POST"])
@jwt_required()
@role_required(Role.ORGANIZER, Role.ADMIN)
def create_event():
    data = request.get_json()
    current_user_id = get_jwt_identity()
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
        price_naira=int(data.get("price_naira", 0)),
        organizer_id=current_user_id
    )
    db.session.add(e)
    db.session.commit()
    return jsonify({"msg": "Created", "event_id": e.id}), 201

@events_bp.route("/<int:event_id>/update", methods=["PATCH"])
@jwt_required()
def update_event(event_id):
    data = request.get_json()
    e = Event.query.get_or_404(event_id)
    current_user_id = get_jwt_identity()
    if e.organizer_id != current_user_id:
        user = User.query.get(current_user_id)
        if user.role != Role.ADMIN:
            return jsonify({"msg": "Not authorized"}), 403
    for field in ["title", "description", "location", "start_time", "end_time", "capacity", "price_naira"]:
        if field in data:
            setattr(e, field, data[field])
    db.session.commit()
    return jsonify({"msg": "Updated"}), 200

@events_bp.route("/<int:event_id>/delete", methods=["DELETE"])
@jwt_required()
def delete_event(event_id):
    e = Event.query.get_or_404(event_id)
    current_user_id = get_jwt_identity()
    if e.organizer_id != current_user_id:
        user = User.query.get(current_user_id)
        if user.role != Role.ADMIN:
            return jsonify({"msg": "Not authorized"}), 403
    db.session.delete(e)
    db.session.commit()
    return jsonify({"msg": "Deleted"}), 200

# ----------------------------
# BOOKINGS BLUEPRINT
# ----------------------------
bookings_bp = Blueprint("bookings", __name__, url_prefix="/api/bookings")

@bookings_bp.route("", methods=["GET"])
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

@bookings_bp.route("/<int:booking_id>", methods=["GET"])
@jwt_required()
def get_booking(booking_id):
    user_id = get_jwt_identity()
    b = Booking.query.get_or_404(booking_id)
    if b.user_id != user_id:
        return jsonify({"msg": "Not authorized"}), 403
    return jsonify({
        "id": b.id, "event_id": b.event_id, "quantity": b.quantity,
        "total_price_naira": b.total_price_naira, "status": b.status
    }), 200

@bookings_bp.route("/create", methods=["POST"])
@jwt_required()
def create_booking():
    data = request.get_json()
    user_id = get_jwt_identity()
    event_id = data.get("event_id")
    quantity = int(data.get("quantity", 1))
    if not event_id or quantity < 1:
        return jsonify({"msg": "event_id and quantity are required"}), 400

    event = Event.query.get_or_404(event_id)
    total_booked = sum(b.quantity for b in event.bookings if b.status == BookingStatus.ACTIVE)
    if event.capacity and (total_booked + quantity) > event.capacity:
        return jsonify({"msg": "Not enough capacity"}), 400

    total_price = event.price_naira * quantity
    booking = Booking(user_id=user_id, event_id=event_id, quantity=quantity, total_price_naira=total_price)
    db.session.add(booking)
    db.session.commit()
    return jsonify({"msg": "Booked", "booking_id": booking.id}), 201

@bookings_bp.route("/cancel/<int:booking_id>", methods=["POST"])
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
    return jsonify({"msg": "Cancelled"}), 200

# ----------------------------
# ADMIN BLUEPRINT
# ----------------------------
admin_bp = Blueprint("admin", __name__, url_prefix="/api/users")

@admin_bp.route("", methods=["GET"])
@jwt_required()
@role_required("admin")
def list_users():
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 20)), 100)
    q = User.query.paginate(page=page, per_page=per_page, error_out=False)
    users = [{"id": u.id, "email": u.email, "role": u.role, "is_active": u.is_active} for u in q.items]
    return jsonify({"users": users, "total": q.total}), 200

@admin_bp.route("/<int:user_id>", methods=["GET"])
@jwt_required()
@role_required("admin")
def get_user(user_id):
    u = User.query.get_or_404(user_id)
    return jsonify({"id": u.id, "email": u.email, "role": u.role, "is_active": u.is_active}), 200

@admin_bp.route("/<int:user_id>/deactivate", methods=["POST"])
@jwt_required()
@role_required("admin")
def deactivate_user(user_id):
    u = User.query.get_or_404(user_id)
    u.is_active = False
    db.session.commit()
    return jsonify({"msg": "User deactivated"}), 200

# ----------------------------
# CREATE APP
# ----------------------------
def create_app():
    app = Flask(__name__)

    # --- Config directly here instead of Config.py ---
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///evvnt.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["JWT_SECRET_KEY"] = "supersecretkey"
    app.config["RESET_PASSWORD_SECRET"] = "anothersecretkey"

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(bookings_bp)
    app.register_blueprint(admin_bp)

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"msg": "Not found"}), 404

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("Server error")
        return jsonify({"msg": "Server error"}), 500

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)