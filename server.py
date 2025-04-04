from flask import Flask, render_template, request, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from cryptography.fernet import Fernet
import threading
import socket
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Generate encryption key
key = Fernet.generate_key()
cipher = Fernet(key)

# Room management
rooms = {}
MAX_USERS = 20
rooms_lock = threading.Lock()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        print(f"[!] Local IP detection failed: {e}")
        return "127.0.0.1"

@app.route('/')
def login():
    return render_template('login.html', server_ip=get_local_ip(), server_port=5555)

@app.route('/login', methods=['POST'])
def handle_login():
    auth_key = request.form.get('serverKey', '').encode()
    if auth_key == key:
        return redirect(url_for('chat'))
    else:
        return render_template('login.html', server_ip=get_local_ip(), server_port=5555, error="Wrong key!")

@app.route('/chat')
def chat():
    return render_template('chat.html', server_ip=get_local_ip(), server_port=5555, server_key=key.decode())

@socketio.on('join')
def handle_join(data):
    print(f"[DEBUG] Join attempt: {data}")
    nickname = data['nickname']
    room = data['room']
    auth_key = data.get('key', '').encode()

    if auth_key != key:
        emit('error', {'message': 'Wrong key!'})
        print(f"[DEBUG] Join failed: Wrong key - {auth_key} vs {key}")
        return

    with rooms_lock:
        if room not in rooms:
            rooms[room] = {'users': [], 'key': Fernet.generate_key()}
        room_data = rooms[room]
        
        if len(room_data['users']) >= MAX_USERS:
            emit('error', {'message': f'Room {room} not found!'})
            print(f"[DEBUG] Join failed: Room {room} full")
            return
        
        if nickname in room_data['users']:
            emit('error', {'message': 'Nickname taken, pick another one!'})
            print(f"[DEBUG] Join failed: Nickname {nickname} taken")
            return
        
        room_data['users'].append(nickname)
        join_room(room)
        room_cipher = Fernet(room_data['key'])
        emit('key', {'room_key': room_data['key'].decode()})
        socketio.emit('message', {'msg': f'{nickname} joined the Secure_Chat_Room!', 'room': room}, room=room)
        print(f"[*] {nickname} joined {room} - Users: {len(room_data['users'])}")

@socketio.on('leave')
def handle_leave(data):
    nickname = data['nickname']
    room = data['room']
    
    with rooms_lock:
        if room in rooms and nickname in rooms[room]['users']:
            rooms[room]['users'].remove(nickname)
            leave_room(room)
            socketio.emit('message', {'msg': f'{nickname} for real?', 'room': room}, room=room)
            print(f"[*] {nickname} left {room} - Users: {len(rooms[room]['users'])}")
            if not rooms[room]['users']:
                del rooms[room]

@socketio.on('message')
def handle_message(data):
    room = data['room']
    msg = data['msg']
    nickname = data['nickname']
    
    with rooms_lock:
        if room in rooms and nickname in rooms[room]['users']:
            room_cipher = Fernet(rooms[room]['key'])
            encrypted_msg = room_cipher.encrypt(f"{nickname}: {msg}".encode())
            socketio.emit('message', {'msg': room_cipher.decrypt(encrypted_msg).decode(), 'room': room}, room=room)

@socketio.on('disconnect')
def handle_disconnect():
    for room, data in list(rooms.items()):
        with rooms_lock:
            for nickname in data['users'][:]:
                if request.sid in [client.sid for client in socketio.server.manager.rooms.get(room, {}).values()]:
                    data['users'].remove(nickname)
                    socketio.emit('message', {'msg': f'{nickname} kicked out!', 'room': room}, room=room)
                    print(f"[*] {nickname} disconnected from {room}")
                    if not data['users']:
                        del rooms[room]
                    break

@socketio.on('connect')
def handle_connect():
    print(f"[*] Client connected: {request.sid} from {request.remote_addr}")

if __name__ == "__main__":
    local_ip = get_local_ip()
    print(f"[SIERRA] Server’s up! Local IP: {local_ip}, Port: 5555, Key: {key.decode()}")
    print(f"[!] Hotspot: http://{local_ip}:5555 | Ngrok: 'ngrok http 5555'")
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 5555)), debug=False, use_reloader=False)