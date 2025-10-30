from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
# We'll use this later for password hashing
from werkzeug.security import generate_password_hash, check_password_hash 
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# --- 1. App Setup ---
app = Flask(__name__)
# This creates a database file named 'tasks.db' in your folder
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SECRET_KEY'] = 'a-very-secret-key-that-you-should-change'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
# If a user tries to access a page they need to be logged in for,
# redirect them to the 'login' page.
login_manager.login_view = 'login'

# --- 2. Database Blueprints (Models) ---

# UserMixin gives us built-in methods for Flask-Login
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    # Store hashed passwords, not plain text!
    password_hash = db.Column(db.String(200), nullable=False)
    
    # Link to the Task model
    # 'tasks' is the name of the relationship
    # 'author' is the name of the back-reference (so we can do task.author)
    tasks = db.relationship('Task', backref='author', lazy=True)

    # Method to set a hashed password
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Method to check the hashed password
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='To Do')
    # This links the task to a user's ID
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# This is required by Flask-Login to get a user from the session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- 3. App Logic (Routes) ---

# --- Authentication Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, send them to the index page
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        # Check if user exists and password is correct
        if user and user.check_password(password):
            login_user(user) # Log the user in
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
            
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please login.', 'warning')
            return redirect(url_for('login'))
        
        # Create new user and hash the password
        new_user = User(username=username)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

@app.route('/logout')
@login_required # Only logged-in users can log out
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Task Routes ---

@app.route('/')
@login_required # Protect this page
def index():
    # Get only the tasks for the currently logged-in user
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', tasks=tasks)

@app.route('/add_task', methods=['POST'])
@login_required
def add_task():
    title = request.form['title']
    if title:
        # Create a new task and link it to the current user
        new_task = Task(title=title, status='To Do', author=current_user)
        db.session.add(new_task)
        db.session.commit()
        flash('Task added!', 'success')
    return redirect(url_for('index'))

@app.route('/update_task/<int:task_id>', methods=['POST'])
@login_required
def update_task(task_id):
    task = Task.query.get_or_404(task_id)
    # Check that the user owns this task
    if task.author != current_user:
        return 'Unauthorized', 403 # Forbidden
        
    task.status = request.form['status']
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/delete_task/<int:task_id>')
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.author != current_user:
        return 'Unauthorized', 403
        
    db.session.delete(task)
    db.session.commit()
    flash('Task deleted.', 'info')
    return redirect(url_for('index'))

# --- 4. Run the App ---
if __name__ == '__main__':
    # We'll create the database file *before* running the app
    with app.app_context():
        db.create_all()
    app.run(debug=True)
