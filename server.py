import eventlet
eventlet.monkey_patch()  # Patch early for Render

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room, leave_room
from cryptography.fernet import Fernet
import threading
import socket
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')  # Render env var
socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory storage
USERS = {}  # {username: password}
ROOMS = {}  # {room_name: {'key': str, 'users': [], 'creator': username}}
MAX_ROOMS = 10
rooms_lock = threading.Lock()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        print(f"[!] Local IP detection fucked: {e}")
        return "127.0.0.1"

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if username in USERS:
            flash("Username taken, pick another, dipshit!")
            return render_template('register.html')
        if not username or not password:
            flash("Fill all fields, asshole!")
            return render_template('register.html')
        USERS[username] = password
        print(f"[DEBUG] User registered: {username}")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        print(f"[DEBUG] Login attempt: username={username}, password={password}")
        if username in USERS and USERS[username] == password:
            session['user'] = username
            print(f"[DEBUG] Login success: {username}")
            return redirect(url_for('choice'))
        flash("Wrong fuckin creds, asshole!")
        print(f"[DEBUG] Login failed: {username}")
    return render_template('login.html')

@app.route('/choice')
def choice():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('choice.html')

@app.route('/create_room', methods=['GET', 'POST'])
def create_room():
    if 'user' not in session:
        return redirect(url_for('login'))
    room_key = None
    if request.method == 'POST':
        room_name = request.form.get('room_name', '').strip()
        print(f"[DEBUG] User {session['user']} creating room: {room_name}")
        with rooms_lock:
            if len(ROOMS) >= MAX_ROOMS:
                flash("Max rooms hit, you fuck!")
                return render_template('create_room.html', room_key=room_key)
            if room_name in ROOMS:
                flash("Room name taken, asshole!")
                return render_template('create_room.html', room_key=room_key)
            if not room_name:
                flash("Enter a room name, dipshit!")
                return render_template('create_room.html', room_key=room_key)
            room_key = Fernet.generate_key().decode()
            ROOMS[room_name] = {'key': room_key, 'users': [], 'creator': session['user']}
            print(f"[DEBUG] Room created: {room_name}, Key: {room_key}")
        return render_template('create_room.html', room_key=room_key, room_name=room_name)
    return render_template('create_room.html', room_key=room_key)

@app.route('/chat_room')
def chat_room():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('chat_room.html')

# SocketIO Events
@socketio.on('join')
def handle_join(data):
    nickname = data['nickname']
    room = data['room']
    room_key = data['room_key']
    if 'user' not in session:
        emit('error', {'message': 'Not logged in, you fuck!'})
        return
    with rooms_lock:
        if room not in ROOMS:
            emit('error', {'message': 'Room doesn’t exist, asshole!'})
            return
        if ROOMS[room]['key'] != room_key:
            emit('error', {'message': 'Wrong room key, dipshit!'})
            return
        if nickname in ROOMS[room]['users']:
            emit('error', {'message': 'Nickname taken, pick another, fuck!'})
            return
        ROOMS[room]['users'].append(nickname)
        join_room(room)
        emit('joined', {'room': room, 'creator': ROOMS[room]['creator']})
        socketio.emit('message', {'msg': f'{nickname} joined the shitshow!', 'room': room}, room=room)
        print(f"[*] {nickname} joined {room} - Users: {len(ROOMS[room]['users'])}")

@socketio.on('leave')
def handle_leave(data):
    nickname = data['nickname']
    room = data['room']
    with rooms_lock:
        if room in ROOMS and nickname in ROOMS[room]['users']:
            ROOMS[room]['users'].remove(nickname)
            leave_room(room)
            socketio.emit('message', {'msg': f'{nickname} fucked off!', 'room': room}, room=room)
            print(f"[*] {nickname} left {room} - Users: {len(ROOMS[room]['users'])}")

@socketio.on('end_room')
def handle_end_room(data):
    room = data['room']
    if 'user' not in session or session['user'] != ROOMS.get(room, {}).get('creator'):
        emit('error', {'message': 'Only the creator can end this shit!'})
        return
    with rooms_lock:
        if room in ROOMS:
            socketio.emit('message', {'msg': f'Room {room} is fuckin done!', 'room': room}, room=room)
            del ROOMS[room]
            print(f"[*] Room {room} ended by {session['user']}")

@socketio.on('message')
def handle_message(data):
    room = data['room']
    msg = data['msg']
    nickname = data['nickname']
    with rooms_lock:
        if room in ROOMS and nickname in ROOMS[room]['users']:
            room_cipher = Fernet(ROOMS[room]['key'].encode())
            encrypted_msg = room_cipher.encrypt(f"{nickname}: {msg}".encode())
            socketio.emit('message', {'msg': room_cipher.decrypt(encrypted_msg).decode(), 'room': room}, room=room)

@socketio.on('disconnect')
def handle_disconnect():
    for room, data in list(ROOMS.items()):
        with rooms_lock:
            for nickname in data['users'][:]:
                if request.sid in [client.sid for client in socketio.server.manager.rooms.get(room, {}).values()]:
                    data['users'].remove(nickname)
                    socketio.emit('message', {'msg': f'{nickname} fucked off!', 'room': room}, room=room)
                    print(f"[*] {nickname} disconnected from {room}")

@socketio.on('connect')
def handle_connect():
    print(f"[*] Client connected: {request.sid} from {request.remote_addr}")

if __name__ == "__main__":
    local_ip = get_local_ip()
    print(f"[SIERRA] Server’s up! Local IP: {local_ip}, Port: 5555")
    print(f"[!] Hotspot: http://{local_ip}:5555")
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 5555)), debug=False)