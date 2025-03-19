# api.py
from flask import Flask, request, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    
    # Create password history table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS password_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Create messages table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        is_public BOOLEAN NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    conn.commit()
    conn.close()

# Initialize the database
init_db()

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400
    
    # Hash the password
    password_hash = generate_password_hash(password)
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    try:
        # Insert the new user
        cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                      (username, email, password_hash))
        user_id = cursor.lastrowid
        
        # Store the password in history
        cursor.execute('INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)',
                      (user_id, password_hash))
        
        conn.commit()
        return jsonify({'message': 'User created successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Username or email already exists'}), 400
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'message': 'Missing required fields'}), 400
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, username, password FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user and check_password_hash(user[2], password):
        return jsonify({'message': 'Login successful', 'user_id': user[0], 'username': user[1]}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/change-password', methods=['POST'])
def change_password():
    data = request.json
    user_id = data.get('user_id')
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not user_id or not current_password or not new_password:
        return jsonify({'message': 'Missing required fields'}), 400
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Check current password
    cursor.execute('SELECT password FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user or not check_password_hash(user[0], current_password):
        conn.close()
        return jsonify({'message': 'Current password is incorrect'}), 401
    
    # Check if new password is in last 3 passwords
    cursor.execute('''
    SELECT password_hash FROM password_history 
    WHERE user_id = ? 
    ORDER BY created_at DESC 
    LIMIT 3
    ''', (user_id,))
    
    password_history = cursor.fetchall()
    
    for old_password in password_history:
        if check_password_hash(old_password[0], new_password):
            conn.close()
            return jsonify({'message': 'New password cannot be one of your last 3 passwords'}), 400
    
    # Update password and add to history
    new_password_hash = generate_password_hash(new_password)
    
    cursor.execute('UPDATE users SET password = ? WHERE id = ?', (new_password_hash, user_id))
    cursor.execute('INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)', 
                  (user_id, new_password_hash))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Password updated successfully'}), 200

@app.route('/api/messages', methods=['POST'])
def create_message():
    data = request.json
    user_id = data.get('user_id')
    content = data.get('content')
    is_public = data.get('is_public', False)
    
    if not user_id or not content:
        return jsonify({'message': 'Missing required fields'}), 400
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('''
    INSERT INTO messages (user_id, content, is_public) 
    VALUES (?, ?, ?)
    ''', (user_id, content, 1 if is_public else 0))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Message created successfully'}), 201

@app.route('/api/messages/<int:user_id>', methods=['GET'])
def get_messages(user_id):
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all public messages and user's private messages
    cursor.execute('''
    SELECT m.id, m.content, m.is_public, m.created_at, u.username 
    FROM messages m
    JOIN users u ON m.user_id = u.id
    WHERE m.is_public = 1 OR m.user_id = ?
    ORDER BY m.created_at DESC
    ''', (user_id,))
    
    messages = []
    for row in cursor.fetchall():
        messages.append({
            'id': row['id'],
            'content': row['content'],
            'is_public': bool(row['is_public']),
            'created_at': row['created_at'],
            'username': row['username']
        })
    
    conn.close()
    
    return jsonify({'messages': messages}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5001)