from collections import defaultdict
import csv
import os
from pathlib import Path

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import EqualTo, InputRequired, Length, ValidationError

from recommendation_engine import RecommendationEngine, split_terms


app = Flask(__name__)
database_url = os.environ.get("DATABASE_URL", "sqlite:///database.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

recommendation_engine = None


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=2, max=20)],
        render_kw={"placeholder": "Enter your username"},
    )
    password = PasswordField(
        validators=[
            InputRequired(),
            Length(min=2, max=20),
            EqualTo("confirm", message="Passwords must match"),
        ],
        render_kw={"placeholder": "Enter your password"},
    )
    confirm = PasswordField(
        validators=[InputRequired(), Length(min=2, max=20)],
        render_kw={"placeholder": "Confirm password"},
    )
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError("That username already exists. Please choose a different one.")


class LoginForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=2, max=20)],
        render_kw={"placeholder": "Username"},
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=2, max=20)],
        render_kw={"placeholder": "Password"},
    )
    submit = SubmitField("Login")


class Artwork(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    artistName = db.Column(db.String(80), nullable=False)
    image = db.Column(db.String(300), nullable=False)
    genres = db.Column(db.String(120))
    styles = db.Column(db.String(120))
    description = db.Column(db.Text)
    completitionYear = db.Column(db.String(20))
    media = db.Column(db.String(120))
    location = db.Column(db.String(200))
    galleries = db.Column(db.String(300))
    tags = db.Column(db.String(300))


class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    artwork_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    favorite = db.Column(db.Boolean, default=False, nullable=False)


def import_csv_to_database(filename):
    csv_path = Path(app.root_path) / filename
    with csv_path.open("r", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            db.session.add(
                Artwork(
                    title=row["title"],
                    artistName=row["artistName"],
                    image=row["image"],
                    genres=row["genres"],
                    styles=row["styles"],
                    description=row["description"],
                    completitionYear=row["completitionYear"],
                    media=row["media"],
                    location=row["location"],
                    galleries=row["galleries"],
                    tags=row["tags"],
                )
            )
        db.session.commit()


def get_recommendation_engine(force_refresh=False):
    global recommendation_engine
    if recommendation_engine is None or force_refresh:
        artworks = Artwork.query.order_by(Artwork.id.asc()).all()
        recommendation_engine = RecommendationEngine(artworks)
    return recommendation_engine


def import_data():
    if not Artwork.query.count():
        import_csv_to_database("artwork.csv")
    get_recommendation_engine(force_refresh=True)


def parse_weight(name, default=50):
    try:
        return int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default


def flash_form_errors(form):
    for field_errors in form.errors.values():
        for error in field_errors:
            flash(error, "danger")


def extract_user_preferences(user_id):
    user_prefs = {
        "artist": defaultdict(int),
        "genre": defaultdict(int),
        "style": defaultdict(int),
    }
    favorites = Favorite.query.filter_by(user_id=int(user_id), favorite=True).all()

    for favorite in favorites:
        artwork = Artwork.query.get(favorite.artwork_id)
        if not artwork:
            continue

        for artist in split_terms(artwork.artistName):
            user_prefs["artist"][artist] += 1
        for genre in split_terms(artwork.genres):
            user_prefs["genre"][genre] += 1
        for style in split_terms(artwork.styles):
            user_prefs["style"][style] += 1

    return user_prefs


def build_recommendation_tags(artwork, user_prefs, weights):
    tag_sources = [
        ("artist", "artist", artwork.artistName),
        ("genre", "genre", artwork.genres),
        ("style", "style", artwork.styles),
    ]
    tags = []

    for category, label, raw_value in tag_sources:
        preferred_terms = set(user_prefs.get(category, {}).keys())
        weight = weights.get(category, 50)

        for term in split_terms(raw_value):
            highlighted = (weight > 0 and term in preferred_terms) or (
                weight < 0 and term not in preferred_terms
            )
            reason = ""
            if highlighted and weight > 0:
                reason = f"Recommended because this {label} matches your favorites: {term}."
            elif highlighted and weight < 0:
                reason = f"Recommended to help you explore a less familiar {label}: {term}."

            tags.append(
                {
                    "category": category,
                    "label": term,
                    "highlighted": highlighted,
                    "reason": reason,
                }
            )

    return tags


def get_similar_artworks(artwork_id):
    artwork = Artwork.query.get_or_404(artwork_id)
    similar_ids = get_recommendation_engine().similar_ids(artwork_id, limit=12)
    similar_rows = Artwork.query.filter(Artwork.id.in_(similar_ids)).all() if similar_ids else []
    similar_by_id = {similar.id: similar for similar in similar_rows}
    return artwork, [similar_by_id[id] for id in similar_ids if id in similar_by_id]


@app.after_request
def add_cache_headers(response):
    if request.path.startswith("/static/"):
        while "Cache-Control" in response.headers:
            response.headers.remove("Cache-Control")
        response.headers["Cache-Control"] = "public, max-age=2592000, immutable"
    return response


@app.route("/")
def home():
    top_artworks = Artwork.query.limit(10).all()
    impressionism_artworks = Artwork.query.filter(Artwork.styles == "Impressionism").limit(10).all()
    romanticism_artworks = Artwork.query.filter(Artwork.styles == "Romanticism").limit(10).all()
    expressionism_artworks = Artwork.query.filter(Artwork.styles == "Expressionism").limit(10).all()
    realism_artworks = Artwork.query.filter(Artwork.styles == "Realism").limit(10).all()
    baroque_artworks = Artwork.query.filter(Artwork.styles == "Baroque").limit(10).all()
    return render_template(
        "guesthome.html",
        top_artworks=top_artworks,
        impressionism_artworks=impressionism_artworks,
        romanticism_artworks=romanticism_artworks,
        realism_artworks=realism_artworks,
        expressionism_artworks=expressionism_artworks,
        baroque_artworks=baroque_artworks,
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        db.session.add(User(username=form.username.data, password=hashed_password))
        db.session.commit()
        flash("Registration successful. You can log in now.", "success")
        return redirect(url_for("login"))
    if request.method == "POST":
        flash_form_errors(form)
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            session["username"] = form.username.data
            flash(f"Welcome back, {user.username}.", "success")
            return redirect(url_for("home"))
        flash("The username or password is incorrect.", "danger")
    elif request.method == "POST":
        flash_form_errors(form)
    return render_template("login.html", form=form)


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    artworks = Artwork.query.limit(30).all()
    return render_template("dashboard.html", artworks=artworks)


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/user-status", methods=["GET"])
def user_status():
    return jsonify({"is_authenticated": current_user.is_authenticated})


@app.route("/favorite")
@login_required
def favorite():
    favorites = (
        db.session.query(Favorite, Artwork)
        .join(Artwork, Favorite.artwork_id == Artwork.id)
        .filter(Favorite.user_id == current_user.id, Favorite.favorite.is_(True))
        .all()
    )
    return render_template("favorite.html", favorites=favorites, current_page="favorite")


@app.route("/check_favorite/<int:artwork_id>")
def check_favorite(artwork_id):
    if not current_user.is_authenticated:
        return jsonify({"status": "unfavorited"})
    favorite = Favorite.query.filter_by(user_id=current_user.id, artwork_id=artwork_id).first()
    return jsonify({"status": "favorited" if favorite else "unfavorited"})


@app.route("/toggle_favorite/<int:artwork_id>", methods=["POST"])
@login_required
def toggle_favorite(artwork_id):
    favorite = Favorite.query.filter_by(user_id=current_user.id, artwork_id=artwork_id).first()
    if not favorite:
        db.session.add(Favorite(user_id=current_user.id, artwork_id=artwork_id, favorite=True))
        db.session.commit()
        return jsonify({"status": "favorited"})

    db.session.delete(favorite)
    db.session.commit()
    return jsonify({"status": "unfavorited"})


@app.route("/artworks/<int:artwork_id>")
def artwork_detail(artwork_id):
    artwork, similar_artworks = get_similar_artworks(artwork_id)
    return render_template("details.html", artwork=artwork, similar_artworks=similar_artworks)


@app.route("/favorite-artworks/<int:artwork_id>")
def favorite_artwork_detail(artwork_id):
    artwork, similar_artworks = get_similar_artworks(artwork_id)
    return render_template("favorite_detail.html", artwork=artwork, similar_artworks=similar_artworks)


@app.route("/recommended-artworks/<int:artwork_id>")
def recommended_detail(artwork_id):
    artwork, similar_artworks = get_similar_artworks(artwork_id)
    return render_template("recommended_detail.html", artwork=artwork, similar_artworks=similar_artworks)


@app.route("/recommendations")
@login_required
def recommendations():
    user_prefs = extract_user_preferences(current_user.id)
    weights = {
        "artist": parse_weight("weight_artist"),
        "genre": parse_weight("weight_genre"),
        "style": parse_weight("weight_style"),
    }
    favorite_ids = [
        favorite.artwork_id
        for favorite in Favorite.query.filter_by(user_id=current_user.id, favorite=True).all()
    ]
    recommendation_results = get_recommendation_engine().recommend(
        user_prefs,
        favorite_ids,
        weights,
        limit=100,
    )

    recommended_ids = [result.artwork_id for result in recommendation_results]
    artwork_rows = Artwork.query.filter(Artwork.id.in_(recommended_ids)).all() if recommended_ids else []
    artwork_by_id = {artwork.id: artwork for artwork in artwork_rows}
    recommended_items = [
        {
            "artwork": artwork_by_id[result.artwork_id],
            "result": result,
            "tags": build_recommendation_tags(artwork_by_id[result.artwork_id], user_prefs, weights),
        }
        for result in recommendation_results
        if result.artwork_id in artwork_by_id
    ]
    recommended_artwork = [item["artwork"] for item in recommended_items]
    recommended_json = [
        {
            "id": item["artwork"].id,
            "artistName": item["artwork"].artistName,
            "genres": item["artwork"].genres,
            "styles": item["artwork"].styles,
            "explanation": item["result"].explanation,
            "matchedTerms": item["result"].matched_terms,
            "explorationTerms": item["result"].exploration_terms,
        }
        for item in recommended_items
    ]
    preference_summary = {category: dict(values) for category, values in user_prefs.items()}

    return render_template(
        "recommendations.html",
        recommended_json=recommended_json,
        recommended_artwork=recommended_artwork,
        recommended_items=recommended_items,
        user_prefs=preference_summary,
        current_page="recommendations",
    )


with app.app_context():
    db.create_all()
    import_data()


if __name__ == "__main__":
    app.run(debug=False)
