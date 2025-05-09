


Secure Chat Room


## Features
- **Clean UI**: Dark mode with cyan, tho customizable to fit your prefernces.
- **Key-Based Login**: Unique key access.
- **Encrypted Rooms**: Messages stay safe with Fernet—pry.
- **Nicknames**: Saves to your alias—localStorage keeps it locked.
- **Multi-Device-Support**: Hotspot local or Ngrok global—chat anywhere.

## Setup
### Prerequisites
- Python 3.8+
- Git
- Termux (Android) or a decent machine
- Ngrok (optional)
- Pydroid3


INSTALLATION
1. Clone using this link:
   ```bash
   git clone https://github.com/Agustasvj/Secure_Chat_Room.git
   cd Secure_Chat_Room
   ```
2. Install the juice:
   ```bash
   pip install -r requirements.txt
   ```
3. Fire it up:
   ```bash
   python chat_server.py
   ```
   - Local: `http://192.168.43.x:5555` (hotspot IP).
   - Phone: `http://10.xxx.xxx.xxx:5555` (Mobile Phone's local ip)
   - Global: 
     ```bash
     ./ngrok http 5555
     ```
     → `https://xyz123.ngrok.io`.

4. Login with the server key (check console)—join a room.

## Dependencies
- Flask: Web backbone.
- Flask-SocketIO: Real-time chat.
- Cryptography: Room encryption.

See `requirements.txt` for the full hit list:
```
Flask==2.3.2
Flask-SocketIO==5.3.6
cryptography==42.0.5
```

## Usage
- **Login**: Punch in the key. Get it from the terminal:
  ```bash
  [SIERRA] Server’s up! Local IP: 192.168.43.x, Port: 5555, Key: abc123...==
  ```
- **Chat**: Pick a nickname, room and start chatting.
- **Hotspot**: Runs on Android and IOS: Termux—host or pydroid:
  ```bash
  pkg install python git
  pip install -r requirements.txt
  python chat_server.py
  ```
- **Ngrok**: Go public—share that URL with your crew:
  ```bash
  ./ngrok http 5555
  ```

## Contributing
Got a wild idea? Fork it, tweak it, PR it—I’ll eyeball it, you crazy bastard:
```bash
git fork https://github.com/Agustasvj/Secure_Chat_Room.git
git checkout -b your-feature
git commit -m "Add some badass shit"
git push origin your-feature
```

## Remarks
Built by [Agustasvj](https://github.com/Agustasvj).
```
*Have fun and chat hard!*
```


