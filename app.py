from flask import Flask,jsonify,request,make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os
import uuid
from passlib.hash import sha256_crypt
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
db=SQLAlchemy(app)
ma=Marshmallow(app)
basedir=os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY']='this is the secret'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///'+os.path.join(basedir,'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password=db.Column(db.String(80))
    admin=db.Column(db.Boolean)

class User_schema(ma.Schema):
    class Meta:
        fields =('id','public_id','name','password','admin')

class Todo(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    text=db.Column(db.String(100))
    complete=db.Column(db.Boolean)
    user_id=db.Column(db.Integer)


class Todo_schema(ma.Schema):
    class Meta:
        fields=('id','text','complete','user_id')

userschema=User_schema()
usersschema=User_schema(many=True)

todoschema=Todo_schema()
todosschema=Todo_schema(many=True)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token=None
        if 'x-access-token' in request.headers:
            token=request.headers['x-access-token']

        if not token:
            return make_response("Unauthorized access",401)

        try:
            data=jwt.decode(token,app.config['SECRET_KEY'])
            current_user=User.query.filter_by(public_id=data['public_id']).first()

        except:
            return make_response("Could not Verify",401,{"Auth_Status":"invalid"})

        return f(current_user,*args,**kwargs)
    return decorated


@app.route("/users/create_user",methods=["POST"])
def create_user():
    data=request.get_json()
    password_hash=sha256_crypt.encrypt(data['password'])

    new_user=User(public_id=str(uuid.uuid1()),name=data['name'],password=password_hash,admin=False)
    db.session.add(new_user)
    db.session.commit()
    return userschema.jsonify(new_user)


@app.route("/users/promote_user/<id>",methods=["PUT"])
@token_required


def promote_user(current_user,id):
    if  not current_user.admin:
        return make_response("You do not have admin previlages",401)
    user=User.query.get(id)
    if not user:
        return make_response("User Does'nt Exist",400)
    user.admin=True
    db.session.commit()

    return jsonify({"status":200,",msg":"user Updated"})


@app.route("/users/get_all_users",methods=["GET"])
@token_required

def get_all_users(current_user):
    if not current_user.admin:
        return make_response("You dont have admin permissions",401) 
    users=User.query.all()
    result=usersschema.dump(users)
    return jsonify(result)


@app.route("/users/get_user/<id>")
@token_required

def get_user(current_user,id):
     if not current_user.admin:
        return make_response("You dont have admin permissions",401) 
     user=User.query.get(id)
     return userschema.jsonify(user)


@app.route("/users/delete_user/<id>",methods=["DELETE"])
@token_required
def delete_user(current_user,id):
    
        
    userdel=User.query.get(id)
    if not current_user.admin:
        return make_response("You dont have admin permissions",401) 
    if not userdel:
        
        return make_response("User doesnt exist",400,{"Query_Status":"failed"})
    db.session.delete(userdel)
    db.session.commit()
    return userschema.jsonify(userdel)

@app.route("/users/login",methods=["POST"])
def login():
    auth=request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response("Could not Verify",401,{"Auth_Status":"invalid"})

    user =User.query.filter_by(name=auth.username).first()

    if not user :
        return make_response("Could not Verify",401,{"Auth_Status":"invalid"})

    if sha256_crypt.verify(auth.password,user.password):
        token=jwt.encode({'public_id':user.public_id,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)},app.config['SECRET_KEY'])

        return jsonify({"token":token.decode('UTF-8')})

    return make_response("Could not Verify",401)


#CRUD ROUTES

@app.route("/todo/get_all_todos",methods=["GET"])
@token_required
def get_all_todos(current_user):
    todos=Todo.query.filter_by(user_id=current_user.id)
    return todosschema.jsonify(todos)

@app.route("/todo/get_todo/<todo_id>",methods=['GET'])
@token_required
def get_todo(current_user,todo_id):
    todo=Todo.query.filter_by(user_id=current_user.id,id=todo_id).first()

    if not todo:
        return make_response("No Todo Found ",400)

    return todoschema.jsonify(todo)


@app.route("/todo/create_todo",methods=['POST'])
@token_required

def create_todo(current_user):
    data=request.get_json()
    new_todo=Todo(text=data['text'],complete=False,user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return todoschema.jsonify(new_todo)


@app.route("/todo/delete_todo/<todo_id>",methods=['DELETE'])
@token_required

def delete_todo(current_user,todo_id):
     todo=Todo.query.filter_by(user_id=current_user.id,id=todo_id).first()

     if not todo:
        return make_response("No Todo Found ",400)

     db.session.delete(todo)
     db.session.commit()

     return todoschema.jsonify(todo)
@app.route("/todo/complete_todo/<todo_id>",methods=['PUT'])
@token_required


def complete_todo(current_user,todo_id):
    todo=Todo.query.filter_by(user_id=current_user.id,id=todo_id).first()
    if not todo:
        return make_response("No Todo Found",400)

    todo.complete=True
    db.session.commit()
    

    return todoschema.jsonify(todo)














if __name__ == '__main__':
    app.run(debug=True)