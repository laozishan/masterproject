from flask import Flask, render_template, url_for, redirect,request,flash,jsonify,session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import EqualTo

from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import csv
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
import re
from sklearn.metrics.pairwise import cosine_similarity

from collections import defaultdict




app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.app_context().push()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Enter your username"})

    password = PasswordField(validators=[InputRequired(), Length(min=2, max=20),EqualTo('confirm', message='Passwords must match')], render_kw={"placeholder": "Enter your password"}
        )
    
    confirm = PasswordField(validators=[
                             InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Confirm password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')




class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')



class Artwork(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    artistName = db.Column(db.String(80), nullable=False)
    image = db.Column(db.String(300), nullable=False)
    genres = db.Column(db.String(120))
    styles = db.Column(db.String(120))
    description = db.Column(db.Text)
    completitionYear = db.Column(db.String(20))
    media=db.Column(db.String(120))
    location=db.Column(db.String(200))
    galleries=db.Column(db.String(300))
    tags=db.Column(db.String(300))






class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    artwork_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    favorite = db.Column(db.Boolean, default=False, nullable=False)



with app.app_context():
    db.create_all()





def import_csv_to_database(filename):
    with open(filename, 'r',encoding='utf-8') as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            artwork = Artwork(
                # id=row['id'],
                title=row['title'],
                artistName=row['artistName'],
                image=row['image'],
                genres=row['genres'],
                styles=row['styles'],
                description=row['description'],
                completitionYear=row['completitionYear'],
                media=row['media'],
                location=row['location'],
                galleries=row['galleries'],
                tags=row['tags']


            )
            db.session.add(artwork)
        db.session.commit()


@app.before_first_request
def import_data():
    # 如果数据库中没有任何数据，则导入 CSV 文件
    if not db.session.query(Artwork).count():
        import_csv_to_database('artwork.csv')



@app.route('/')
def home():
    total = Artwork.query.count()
    print(total)

    top_artworks = Artwork.query.limit(10).all()

    impressionism_artworks = Artwork.query.filter(Artwork.styles == 'Impressionism').limit(10).all()

    romanticism_artworks = Artwork.query.filter(Artwork.styles == 'Romanticism').limit(10).all()

    expressionism_artworks = Artwork.query.filter(Artwork.styles == 'Expressionism').limit(10).all()

    realism_artworks = Artwork.query.filter(Artwork.styles == 'Realism').limit(10).all()

    baroque_artworks = Artwork.query.filter(Artwork.styles == 'Baroque').limit(10).all()
    return render_template('guesthome.html', top_artworks=top_artworks,impressionism_artworks =impressionism_artworks,romanticism_artworks=romanticism_artworks,realism_artworks=realism_artworks,expressionism_artworks=expressionism_artworks,baroque_artworks=baroque_artworks,current_user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if  form.validate_on_submit() :
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        print(new_user)
        return redirect(url_for('login'))
    return render_template('register.html',form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        print(user)
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                session['username'] = form.username.data 
    
                return redirect(url_for('home'))
    return render_template('login.html',form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    artworks = db.session.query(Artwork).limit(30).all()
    return render_template('dashboard.html',artworks=artworks)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))





@app.route('/user-status', methods=['GET'])
def user_status():
    is_authenticated = current_user.is_authenticated
    return jsonify({'is_authenticated': is_authenticated})






@app.route('/favorite')
@login_required
def favorite():
    favorites = (
        db.session.query(Favorite, Artwork)
        .join(Artwork, Favorite.artwork_id == Artwork.id)
        .filter(Favorite.user_id == current_user.id, Favorite.favorite == True)
        .all()
    )
    current_page='favorite'
    return render_template('favorite.html', favorites=favorites,current_page=current_page)




@app.route('/check_favorite/<int:artwork_id>')
def check_favorite(artwork_id):
    favorite = Favorite.query.filter_by(user_id=current_user.id, artwork_id=artwork_id).first()
    if favorite:
        return jsonify({'status': 'favorited'})
    else:
        return jsonify({'status': 'unfavorited'})





@app.route('/toggle_favorite/<int:artwork_id>', methods=['POST'])
@login_required
def toggle_favorite(artwork_id):
    favorite = Favorite.query.filter_by(user_id=current_user.id, artwork_id=artwork_id).first()
    if not favorite:
        favorite = Favorite(user_id=current_user.id, artwork_id=artwork_id, favorite=True)
        db.session.add(favorite)
        db.session.commit()
        return jsonify({'status': 'favorited'})
    else:
        db.session.delete(favorite)
        db.session.commit()
        return jsonify({'status': 'unfavorited'})




def get_similar_artworks(artwork_id):
    artworks = Artwork.query.all()
    corpus = [artwork.title + " " + artwork.artistName + " " + artwork.genres + " " + artwork.styles for artwork in artworks]

    vectorizer = TfidfVectorizer()
    tfidf_matrix = vectorizer.fit_transform(corpus)

    artwork = Artwork.query.get(artwork_id)

    query = artwork.title + " " + artwork.artistName + " " + artwork.genres + " " + artwork.styles
    query_vec = vectorizer.transform([query])

    similarity_scores = cosine_similarity(query_vec, tfidf_matrix)[0]

    top_indices = similarity_scores.argsort()[::-1][1:11]

    similar_artworks = [artworks[i] for i in top_indices]

    return artwork, similar_artworks


@app.route('/artworks/<int:artwork_id>')
def artwork_detail(artwork_id):
    artwork, similar_artworks = get_similar_artworks(artwork_id)
    return render_template('details.html', artwork=artwork, similar_artworks=similar_artworks)


@app.route('/favorite-artworks/<int:artwork_id>')
def favorite_artwork_detail(artwork_id):
    artwork, similar_artworks = get_similar_artworks(artwork_id)
    return render_template('favorite_detail.html', artwork=artwork, similar_artworks=similar_artworks)


@app.route('/recommended-artworks/<int:artwork_id>')
def recommended_detail(artwork_id):
    artwork, similar_artworks = get_similar_artworks(artwork_id)
    return render_template('recommended_detail.html', artwork=artwork, similar_artworks=similar_artworks)





def extract_user_preferences(user_id):

    user_prefs = {
        'artist': defaultdict(int),
        'genre': defaultdict(int),
        'style': defaultdict(int),

    }

    favorites = Favorite.query.filter_by(user_id=user_id, favorite=True).all()

    for favorite in favorites:
        
        artwork = Artwork.query.get(favorite.artwork_id)
        artwork_artist = set(artwork.artistName.split(", "))
        artwork_genres = set(artwork.genres.split(", "))
        artwork_styles = set(artwork.styles.split(", "))

        for artist in artwork_artist:
            user_prefs['artist'][artist] += 1

        for genre in artwork_genres:
            user_prefs['genre'][genre] += 1

        for style in artwork_styles:
            user_prefs['style'][style] += 1


    print(user_prefs)

    return user_prefs

def recommend_artwork(user_prefs, weight_artist, weight_genre, weight_style):
    # Initialize artwork scores dictionary
    artwork_scores = defaultdict(int)
    user_id=current_user.id

    # Loop over all artwork in database
    for artwork in Artwork.query.all():
        # Skip artwork that user has already favorited
        if Favorite.query.filter_by(user_id=user_id, artwork_id=artwork.id, favorite=True).first():
            continue


        artwork_artist = set(artwork.artistName.split(", "))
        artwork_genres = set(artwork.genres.split(", "))
        artwork_styles = set(artwork.styles.split(", "))
        

        # Calculate Jaccard similarity scores
        artist_score = len(user_prefs['artist'].keys() & artwork_artist) / len(user_prefs['artist'].keys() | artwork_artist)
        genre_score = len(user_prefs['genre'].keys() & artwork_genres) / len(user_prefs['genre'].keys() | artwork_genres)
        style_score = len(user_prefs['style'].keys() & artwork_styles) / len(user_prefs['style'].keys() | artwork_styles)

        overall_score = (weight_artist * artist_score) + (weight_genre * genre_score) + (weight_style * style_score) 
        # Add artwork score to dictionary
        artwork_scores[artwork] = overall_score

    # Sort artwork by score, from highest to lowest
    recommended_artwork = sorted(artwork_scores.items(), key=lambda x: x[1], reverse=True)


    return [artwork for artwork, _ in recommended_artwork]

@app.route('/recommendations')
@login_required
def recommendations():
    # Get user id from query parameters
    user_id = request.args.get('user_id')
    print(user_id)

    # Extract user preferences from favorites
    user_prefs = extract_user_preferences(user_id)
  # 获取权重参数，如果没有则使用默认值 50
    weight_artist = int(request.args.get('weight_artist', 50))
    weight_genre = int(request.args.get('weight_genre', 50))
    weight_style = int(request.args.get('weight_style', 50))
    print(weight_artist,weight_genre,weight_style)

        # Get recommended artwork based on user preferences and weights
    recommended_artwork = recommend_artwork(user_prefs, weight_artist, weight_genre, weight_style)[0:100]

    # Convert recommended artwork to a list of dictionaries
    recommended_json = [
        {
            'id': artwork.id,
            'artistName': artwork.artistName,
            'genres': artwork.genres,
            'styles': artwork.styles
        }
        for artwork in recommended_artwork
    ]
    current_page='recommendations'



    return render_template('recommendations.html', recommended_json=recommended_json,recommended_artwork=recommended_artwork,user_prefs=user_prefs,current_page=current_page)




if __name__ == "__main__":
    app.run(debug=True)
