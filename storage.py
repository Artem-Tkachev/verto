import json
import os

USERS_FILE = 'users.json'

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

WORKOUTS_FILE = 'workouts.json'

def load_workouts():
    if os.path.exists(WORKOUTS_FILE):
        with open(WORKOUTS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_workouts(workouts):
    with open(WORKOUTS_FILE, 'w') as f:
        json.dump(workouts, f)

CHALLENGES_FILE = 'challenges.json'

def load_challenges():
    if os.path.exists(CHALLENGES_FILE):
        with open(CHALLENGES_FILE, 'r') as f:
            return json.load(f)
    return []

def save_challenges(challenges):
    with open(CHALLENGES_FILE, 'w') as f:
        json.dump(challenges, f)