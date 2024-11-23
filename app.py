from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId

app = Flask(__name__)

# Configuração do JWT
app.config['JWT_SECRET_KEY'] = 'secreta'  # Defina a chave secreta para o JWT
jwt = JWTManager(app)

# Configuração do MongoDB
app.config["MONGO_URI"] = "mongodb://localhost:27017/usuarios_db"  # Altere para o seu banco de dados
mongo = PyMongo(app)

# Rota de registro
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"msg": "No data provided"}), 400

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"msg": "Email e senha são obrigatórios"}), 400

    # Verificando se o usuário já existe
    user = mongo.db.users.find_one({"email": email})
    if user:
        return jsonify({"msg": "Usuário já existe"}), 400

    hashed_password = generate_password_hash(password)
    mongo.db.users.insert_one({"email": email, "password": hashed_password})

    return jsonify({"msg": "Usuário criado com sucesso"}), 201

# Função para realizar login e gerar token
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data.get('email') or not data.get('password'):
        return jsonify({"msg": "Email e senha são obrigatórios"}), 400

    email = data.get('email')
    password = data.get('password')

    user = mongo.db.users.find_one({"email": email})
    if not user or not check_password_hash(user['password'], password):
        return jsonify({"msg": "Credenciais inválidas"}), 401

    access_token = create_access_token(identity=email)
    return jsonify({"access_token": access_token}), 200

# Função para acessar o perfil do usuário
@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    current_user = get_jwt_identity()
    return jsonify({
        'msg': 'Perfil acessado com sucesso',
        'email': current_user
    })

# Função para criar um novo item (apenas para usuários autenticados)
@app.route('/items', methods=['POST'])
@jwt_required()
def create_item():
    data = request.get_json()
    item_name = data.get('name')
    
    if not item_name:
        return jsonify({"msg": "Nome do item é obrigatório"}), 400

    item = {
        "name": item_name,
        "created_by": get_jwt_identity()
    }
    item_id = mongo.db.items.insert_one(item).inserted_id

    # Retornando o ObjectId do item recém-criado
    return jsonify({
        "msg": "Item criado com sucesso",
        "item_id": str(item_id)  # Convertendo o ObjectId para string para retorno
    }), 201

# Função para atualizar um item (apenas para usuários autenticados)
@app.route('/items/<id>', methods=['PUT'])
@jwt_required()
def update_item(id):
    try:
        item_id = ObjectId(id)
    except:
        return jsonify({"msg": "ID do item inválido"}), 400
    
    data = request.get_json()
    item_name = data.get('name')
    item_price = data.get('price')  # Novo campo para o preço
    
    if not item_name and item_price is None:  # Verificando se pelo menos um campo foi passado
        return jsonify({"msg": "Nome do item ou preço são obrigatórios"}), 400

    update_fields = {}

    if item_name:
        update_fields["name"] = item_name
    if item_price is not None:
        update_fields["price"] = item_price  # Atualizando o preço

    # Atualiza o item no banco de dados
    result = mongo.db.items.update_one(
        {"_id": item_id, "created_by": get_jwt_identity()},
        {"$set": update_fields}  # Atualiza apenas os campos que foram passados
    )

    if result.matched_count == 0:
        return jsonify({"msg": "Item não encontrado ou você não tem permissão para editá-lo"}), 404
    
    return jsonify({"msg": "Item atualizado com sucesso"}), 200

# Função para excluir um item (apenas para usuários autenticados)
@app.route('/items/<id>', methods=['DELETE'])
@jwt_required()
def delete_item(id):
    try:
        item_id = ObjectId(id)
    except:
        return jsonify({"msg": "ID do item inválido"}), 400

    result = mongo.db.items.delete_one(
        {"_id": item_id, "created_by": get_jwt_identity()}
    )

    if result.deleted_count == 0:
        return jsonify({"msg": "Item não encontrado ou você não tem permissão para excluí-lo"}), 404
    
    return jsonify({"msg": "Item excluído com sucesso"}), 200

if __name__ == '__main__':
    app.run(debug=True)


