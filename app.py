from flask import Flask, request, jsonify
from models.user import User
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from database import db
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)
#view login
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/login', methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        #login
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message": "Authentication successfull"})
    
    return jsonify({"message": "Invalid credentials."}), 400

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({"message":"You have logged out"})

@app.route('/user', methods=['POST'])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        user = User(username=username, password=hashed_password, role='user')
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": f"{username} successfully registered"})

    return jsonify({"message": "Invalid data"}), 400

@app.route('/user/<int:id_user>', methods=['GET'])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)

    if user:
        return {"username": user.username}
    
    return jsonify({"message": "User not found"}), 404

@app.route('/user/<int:id_user>', methods=['PUT'])
@login_required
def update_user(id_user):
    data = request.json
    user = User.query.get(id_user)

    if id_user != current_user.id and current_user.role == 'user':
        return jsonify({"message":"You do not have permission to perform this action."}), 403

    if user and data.get("password"):
        user.password = data.get("password")
        db.session.commit()
        return jsonify({"message": f"User {id_user} password updated"})
    
    return jsonify({"message": "User not found"}), 404

@app.route('/user/<int:id_user>', methods=['DELETE'])
@login_required
def delete_user(id_user):
    user = User.query.get(id_user)

    if current_user.role != 'admin':
        return jsonify({"message":"You do not have permission to perform this action."}), 403

    if user and id_user != current_user.id:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message":f"User {id_user} successfully deleted."})
    
    return jsonify({"message": "You cant delete your own account"}), 404

if __name__ == '__main__':
    app.run(debug=True)