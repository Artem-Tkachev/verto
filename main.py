from flask import Flask, request, jsonify, render_template, redirect, session, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from storage import load_users, save_users, load_workouts, save_workouts, load_challenges, save_challenges
import uuid
from datetime import datetime

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
        "password": generate_password_hash(data.get("password")),
        "favorite_routes": [],
        "challenges": {
            "sent": [],
            "received": []
        }
    }
    save_users(users)
    return jsonify({"msg": "User registered"}), 201

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

@app.route('/my_workouts_html')
def get_my_workouts_html():
    token = session.get('token')
    if not token:
        return redirect(url_for('login_html'))

    from flask_jwt_extended import decode_token
    username = decode_token(token)['sub']

    if "favorite_routes" not in users[username]:
        users[username]["favorite_routes"] = []
        save_users(users)

    user_workouts = [w for w in workouts if w["user_name"] == username]
    favorite_ids = users[username]["favorite_routes"]

    return render_template("my_workouts.html", workouts=user_workouts, favorite_ids=favorite_ids)

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

import json

@app.route('/workout/<id>')
def view_workout(id):
    workout = next((w for w in workouts if w["id"] == id), None)
    if not workout:
        return "Тренировка не найдена", 404

    if isinstance(workout["map"], str):
        try:
            workout["map"] = json.loads(workout["map"])
        except:
            workout["map"] = []

    return render_template("view_workout.html", workout=workout)

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        username = request.form.get('username')
        return redirect(url_for('public_workouts', username=username))
    return render_template('search.html')

@app.route('/api/search_users')
def api_search_users():
    query = request.args.get('q', '').lower()
    if not query:
        return jsonify([])

    matches = [u for u in users.keys() if u.lower().startswith(query)]
    return jsonify(matches[:10])

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

@app.route('/route/<map_id>/leaderboard')
def route_leaderboard(map_id):
    sort_by = request.args.get("sort", "speed")

    relevant_workouts = [w for w in workouts if w.get("map") == map_id]
    if not relevant_workouts:
        return f"Для маршрута {map_id} ещё нет тренировок."

    for w in relevant_workouts:
        w["speed"] = w["distance"] / w["duration"] if w["duration"] else 0

    if sort_by == "duration":
        leaderboard = sorted(relevant_workouts, key=lambda x: x["duration"])
    else:
        leaderboard = sorted(relevant_workouts, key=lambda x: x["speed"], reverse=True)

    return render_template("leaderboard.html", map_id=map_id, leaderboard=leaderboard, sort_by=sort_by)


@app.route('/challenge/<workout_id>', methods=['POST'])
def send_challenge(workout_id):
    token = session.get('token')
    if not token:
        return redirect(url_for('login_html'))

    from flask_jwt_extended import decode_token
    sender = decode_token(token)['sub']
    to_user = request.form.get("to_user")

    if to_user not in users:
        return "Пользователь не найден", 404

    challenge_id = str(uuid.uuid4())
    challenge = {
        "id": challenge_id,
        "from": sender,
        "to": to_user,
        "workout_id": workout_id,
        "status": "pending",
        "created_at": datetime.now().isoformat()
    }

    challenges = load_challenges()
    challenges.append(challenge)
    save_challenges(challenges)

    users[sender]["challenges"]["sent"].append(challenge_id)
    users[to_user]["challenges"]["received"].append(challenge_id)
    save_users(users)

    return redirect(url_for('get_my_workouts_html'))
    
@app.route('/challenges')
def view_challenges():
    token = session.get('token')
    if not token:
        return redirect(url_for('login_html'))

    from flask_jwt_extended import decode_token
    username = decode_token(token)['sub']

    user = users.get(username)
    if not user:
        return "Пользователь не найден", 404

    challenges = load_challenges()

    sent = [c for c in challenges if c["id"] in user.get("challenges", {}).get("sent", [])]
    received = [c for c in challenges if c["id"] in user.get("challenges", {}).get("received", [])]

    return render_template("challenges.html", sent=sent, received=received, username=username)

@app.route('/challenge/<challenge_id>/accept', methods=['POST'])
def accept_challenge(challenge_id):
    challenges = load_challenges()
    for c in challenges:
        if c["id"] == challenge_id:
            c["status"] = "accepted"
            save_challenges(challenges)
            break
    return redirect(url_for('view_challenges'))

@app.route('/challenge/<challenge_id>/decline', methods=['POST'])
def decline_challenge(challenge_id):
    challenges = load_challenges()
    for c in challenges:
        if c["id"] == challenge_id:
            c["status"] = "declined"
            save_challenges(challenges)
            break
    return redirect(url_for('view_challenges'))

@app.route('/challenge/<challenge_id>/complete', methods=['POST'])
def complete_challenge(challenge_id):
    challenges = load_challenges()
    for c in challenges:
        if c["id"] == challenge_id:
            c["status"] = "completed"
            save_challenges(challenges)
            break
    return redirect(url_for('view_challenges'))


if __name__ == '__main__':
    port = 8080
    app.run(app, host='0.0.0.0', port=port)