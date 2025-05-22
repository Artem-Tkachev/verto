from flask import Flask, request, jsonify, render_template, redirect, session, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from storage import load_users, save_users, load_workouts, save_workouts

app = Flask('verto')
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
app.secret_key = 'key'
jwt = JWTManager(app)

users = load_users()
workouts = load_workouts()

@app.route('/')
def index():
    token = session.get('token')
    username = None
    if token:
        from flask_jwt_extended import decode_token
        try:
            username = decode_token(token)['sub']
        except Exception:
            session.pop('token', None)
            username = None
    return render_template('index.html', username=username)

@app.route('/logout')
def logout():
    session.pop('token', None)
    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    if username in users:
        return jsonify({"msg": "User already exists"}), 400
    users[username] = {
        "password": generate_password_hash(data.get("password"))
    }
    save_users(users)
    return jsonify({"msg": "User registered"}), 201

@app.route('/login/', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    user = users.get(username)
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"msg": "Bad login"}), 401
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200

@app.route('/workouts/', methods=['POST'])
@jwt_required()
def upload_workout():
    current_user = get_jwt_identity()
    data = request.get_json()
    workout = {
        "user_name": current_user,
        "training_name": data.get("training_name"),
        "type": data.get("type"),
        "distance": data.get("distance"),
        "duration": data.get("duration"),
        "map": data.get("map")
    }
    workouts.append(workout)
    return jsonify({"msg": "Workout saved"}), 201

@app.route('/my_workouts/', methods=['GET'])
@jwt_required()
def get_my_workouts():
    current_user = get_jwt_identity()
    user_workouts = [w for w in workouts if w["user_name"] == current_user]
    return jsonify(user_workouts), 200

@app.route('/register_html', methods=['GET', 'POST'])
def register_html():
    if request.method == 'POST':
        data = request.form
        username = data.get("username")
        if username in users:
            return "User already exists"
        users[username] = {
            "password": generate_password_hash(data.get("password"))
        }
        save_users(users)
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login_html', methods=['GET', 'POST'])
def login_html():
    if request.method == 'POST':
        data = request.form
        username = data.get("username")
        password = data.get("password")
        user = users.get(username)
        if not user:
            return '''
            <p>Пользователя с таким именем не существует, проверьте правильность написания или создайте новый аккаунт</p>
            <p><a href="/login_html">Назад</a></p>
            '''
        if not check_password_hash(user["password"], password):
            return '''
            <p>Неправильный пароль, попробуйте еще раз или создайте новый аккаунт</p> 
            <p><a href="/login_html">Назад</a></p>
            '''
        token = create_access_token(identity=username)
        session['token'] = token
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_html():
    if request.method == 'POST':
        token = session.get('token')
        if not token:
            return "Вы не авторизованы", 401

        from flask_jwt_extended import decode_token
        identity = decode_token(token)['sub']

        data = request.form
        workout = {
            "user_name": identity,
            "training_name": data.get("training_name"),
            "type": data.get("type"),
            "distance": float(data.get("distance")),
            "duration": int(data.get("duration")),
            "map": data.get("map")
        }
        if not all([data.get("training_name"), data.get("type"), data.get("distance"),
            data.get("duration"), data.get("map")]):
            return "Пожалуйста, заполните все поля", 400
        workouts.append(workout)
        save_workouts(workouts)
        return '''
        <p>Тренировка загружена</p>
        <p><a href="/">Назад</a></p>
        '''

    return render_template('upload.html')

@app.route('/my_workouts_html')
def my_workouts_html():
    token = session.get('token')
    if not token:
        return redirect(url_for('login_html'))

    from flask_jwt_extended import decode_token
    identity = decode_token(token)['sub']

    user_workouts = [w for w in workouts if w["user_name"] == identity]
    return render_template('my_workouts.html', workouts=user_workouts)

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        username = request.form.get('username')
        return redirect(url_for('public_workouts', username=username))
    return render_template('search.html')

@app.route('/public/<username>')
def public_workouts(username):
    if username not in users:
        return f"Пользователь {username} не найден", 404

    user_workouts = [w for w in workouts if w["user_name"] == username]
    return render_template('public_workouts.html', username=username, workouts=user_workouts)

@app.route('/favorite/<route_id>', methods=['POST'])
def toggle_favorite(route_id):
    token = session.get('token')
    if not token:
        return "Вы не авторизованы", 401

    from flask_jwt_extended import decode_token
    username = decode_token(token)['sub']

    if username not in users:
        return "Пользователь не найден", 404

    if "favorite_routes" not in users[username]:
        users[username]["favorite_routes"] = []

    if route_id in users[username]["favorite_routes"]:
        users[username]["favorite_routes"].remove(route_id)
    else:
        users[username]["favorite_routes"].append(route_id)

    save_users(users)
    return redirect(url_for('index'))

@app.route('/favorites')
def show_favorites():
    token = session.get('token')
    if not token:
        return redirect(url_for('login_html'))

    from flask_jwt_extended import decode_token
    username = decode_token(token)['sub']

    if username not in users:
        return "Пользователь не найден", 404

    fav_ids = users[username].get("favorite_routes", [])
    fav_workouts = [w for w in workouts if w.get("id") in fav_ids]

    return render_template('favorites.html', workouts=fav_workouts)

if __name__ == '__main__':
    port = 8080
    app.run(app, host='0.0.0.0', port=port)