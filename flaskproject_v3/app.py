# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import requests
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)

# API endpoint
API_URL = "http://localhost:5001"

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        response = requests.post(f"{API_URL}/api/signup", json={
            'username': username,
            'email': email,
            'password': password
        })
        
        if response.status_code == 201:
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            error = response.json().get('message', 'An error occurred')
            flash(error, 'danger')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        response = requests.post(f"{API_URL}/api/login", json={
            'username': username,
            'password': password
        })
        
        if response.status_code == 200:
            data = response.json()
            session['user_id'] = data['user_id']
            session['username'] = data['username']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    # Get all public messages and user's private messages
    response = requests.get(f"{API_URL}/api/messages/{session['user_id']}")
    messages = response.json().get('messages', [])
    
    return render_template('dashboard.html', username=session['username'], messages=messages)

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('change_password'))
        
        response = requests.post(f"{API_URL}/api/change-password", json={
            'user_id': session['user_id'],
            'current_password': current_password,
            'new_password': new_password
        })
        
        if response.status_code == 200:
            flash('Password changed successfully', 'success')
            return redirect(url_for('dashboard'))
        else:
            error = response.json().get('message', 'An error occurred')
            flash(error, 'danger')
    
    return render_template('change_password.html')

@app.route('/post-message', methods=['GET', 'POST'])
def post_message():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        content = request.form['content']
        is_public = 'is_public' in request.form
        
        response = requests.post(f"{API_URL}/api/messages", json={
            'user_id': session['user_id'],
            'content': content,
            'is_public': is_public
        })
        
        if response.status_code == 201:
            flash('Message posted successfully', 'success')
        else:
            flash('Failed to post message', 'danger')
        
        return redirect(url_for('dashboard'))
    
    return render_template('post_message.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)