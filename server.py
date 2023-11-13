import threading
import uuid
from flask import Flask
from cryptography.hazmat.primitives import serialization
import sqlite3
from flask import request, abort
from cryptography.hazmat.primitives import hashes
import json
import base64
import time
from threading import Lock


def setup_database(connection: sqlite3.Connection):
    cur = connection.cursor()
    cur.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='users'")
    if cur.fetchone()[0] != 1:
        cur.execute("""
        CREATE TABLE users(
        username TEXT PRIMARY KEY ,
        pub_key TEXT,
        pass_hash TEXT
        )
        """)
    cur.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='messages'")
    if cur.fetchone()[0] != 1:
        cur.execute("""
        CREATE TABLE messages(
        msg_id INTEGER PRIMARY KEY ,
        sender TEXT,
        receiver TEXT,
        text TEXT,
        timestamp INTEGER,
        FOREIGN KEY(sender) REFERENCES users(username),
        FOREIGN KEY(receiver) REFERENCES users(username)
        )
        """)


class Token:
    def __init__(self, expiration: int, username: str):
        self.value: str = uuid.uuid1().hex
        self.timestamp: int = int(time.time())
        self.expiration: int = self.timestamp + expiration
        self.username: str = username

    def is_expired(self) -> bool:
        return self.expiration >= self.timestamp


con = sqlite3.connect("database.db", check_same_thread=False)
con_lock = threading.Lock()

token_table: dict[str, Token] = dict()
token_lock = threading.Lock()

setup_database(con)

app = Flask(__name__)
with open("private_key", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

with open("public_key", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
    )

with open("public_key", "r") as key_file:
    public_key_string = key_file.read()


def hash_password(password):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode())
    pass_hash = base64.b64encode(digest.finalize()).decode('utf-8')
    return pass_hash


@app.route("/register", methods=["POST"])
def register():
    data: dict | str = request.get_json(silent=False)
    if type(dict) is str:
        data = json.loads(data)
    if ("username" not in data.keys() or
            "password" not in data.keys() or
            "public_key" not in data.keys()):
        abort(400)
    pass_hash = hash_password(data['password'] + data['username'])
    with con_lock:
        res = con.execute("SELECT * FROM users WHERE username=?", (data['username'],)).fetchone()
        if res:
            abort(409)
        con.execute("INSERT INTO users VALUES(?,?,?)", (data['username'], data['public_key'], pass_hash))
        con.commit()

    token = Token(3600, data['username'])
    with token_lock:
        token_table[data['username']] = token

    return json.dumps({'public_key': public_key_string, 'token': token.value}), 201


@app.route("/login", methods=["POST"])
def login():
    data: dict = request.get_json(silent=False)
    if ("username" not in data.keys() or
            "password" not in data.keys()):
        abort(400)
    with con_lock:
        res = con.execute("SELECT * FROM users WHERE username=?", (data['username'],)).fetchone()
        if not res:
            abort(401)
        pass_hash = hash_password(data['password'] + data['username'])
        if res[2] != pass_hash:
            abort(401)
        if "public_key" in data.keys():
            con.execute("UPDATE users SET pub_key=? WHERE username=?",
                        (data['public_key'], data['username']))
        con.commit()

    token = Token(3600, data['username'])
    with token_lock:
        token_table[data['username']] = token

    return json.dumps({'server_generated_public_key': public_key_string, 'token': token.value})


@app.route("/message", methods=["POST"])
def send_message():
    data: dict = request.get_json(silent=False)
    if ("receiver" not in data.keys() or
            "text" not in data.keys()):
        abort(400)
    if "Authorization" not in request.headers.keys():
        abort(400)

    token = request.headers.get("token")
    with token_lock:
        if data['username'] not in token_table.keys():
            abort(403)
        if token != token_table[data['username']].value:
            abort(403)
        if token_table[data['username']].is_expired():
            abort(403)
    with con_lock:
        con.execute("INSERT INTO messages(sender, receiver, text, timestamp) VALUES(?, ?, ?, ?)",
                    (data['username'], '', data['text'], int(time.time())))
        con.commit()
    return '', 200


@app.route("/", methods=["GET"])
def get_messages():
    if "token" not in request.headers.keys():
        abort(400)

    token = request.headers.get("token")
    with token_lock:
        for t in token_table.values():
            if token == t.value:
                token = t
                break
        else:
            abort(403)

    with con_lock:
        pub_key = con.execute("SELECT pub_key FROM users WHERE username=?",
                              (token.username,))
        if not pub_key:
            abort(404)
        msgs = con.execute("SELECT * FROM messages").fetchall()

    pub_key = pub_key.fetchone()[0]
    print(pub_key)
    return "Hello message"
