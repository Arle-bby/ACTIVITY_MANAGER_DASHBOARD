from flask import Flask, render_template, session, redirect, url_for, request
from pymongo import MongoClient
from flask import flash
from datetime import datetime, timezone
import os
import requests

app = Flask(__name__)
app.secret_key = os.urandom(24) # Para mantener las sesiones seguras

# Configuración
MONGO_URL = os.getenv('MONGO_URL')
CLIENT_ID = os.getenv('DISCORD_CLIENT_ID')
CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
REDIRECT_URI = os.getenv('DISCORD_REDIRECT_URI')
API_ENDPOINT = 'https://discord.com/api/v10'

def get_db():
    client = MongoClient(MONGO_URL)
    return client["albion_db"]

@app.route('/')
def index():
    if 'token' not in session:
        return render_template('login.html')
    
    headers = {'Authorization': f"Bearer {session['token']}"}
    user_guilds = requests.get("https://discord.com/api/v10/users/@me/guilds", headers=headers).json()
    
    # Verificación del Bot Token
    bot_token = os.getenv('DISCORD_TOKEN')
    bot_headers = {'Authorization': f"Bot {bot_token}"}
    bot_guilds_resp = requests.get("https://discord.com/api/v10/users/@me/guilds", headers=bot_headers).json()
    
    # Si Discord devuelve un error en lugar de una lista, lo capturamos aquí
    if isinstance(bot_guilds_resp, dict) and "message" in bot_guilds_resp:
        return f"Error de Discord API (Bot Token): {bot_guilds_resp['message']}. Verifica el DISCORD_TOKEN en Render.", 500

    bot_guild_ids = [g['id'] for g in bot_guilds_resp]
    
    final_guilds = []
    for g in user_guilds:
        # Permiso de Administrador es 0x8
        is_admin = (int(g['permissions']) & 0x8) == 0x8
        if is_admin and g['id'] in bot_guild_ids:
            final_guilds.append(g)
            
    return render_template('select_server.html', guilds=final_guilds)

@app.route('/dashboard/<guild_id>')
def server_dashboard(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    
    db = get_db()
    # Buscamos plantillas y parties filtradas por ese servidor específico
    parties = list(db["parties"].find({"guild_id": int(guild_id)}).sort("createdAt", -1))
    templates = list(db["custom_templates"].find({"guild_id": int(guild_id)}))
    
    return render_template('index.html', parties=parties, templates=templates, guild_id=guild_id)

@app.route('/login')
def login():
    scope = "identify guilds"
    auth_url = f"https://discord.com/api/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope={scope}"
    return redirect(auth_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = requests.post(f"{API_ENDPOINT}/oauth2/token", data=data, headers=headers)
    session['token'] = r.json().get('access_token')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/create_template/<guild_id>', methods=['POST'])
def create_template(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    
    # Obtenemos los datos del formulario
    nombre = request.form.get('nombre')
    roles_input = request.form.get('roles') # Formato: Tanque:1, Healer:2
    
    try:
        # Convertimos el texto "Rol:Cantidad" en un diccionario de Python
        roles_dict = {}
        for item in roles_input.split(','):
            partes = item.split(':')
            if len(partes) == 2:
                roles_dict[partes[0].strip()] = int(partes[1].strip())
        
        # Guardamos en la base de datos
        db = get_db() # Usando la función que ya teníamos
        db["custom_templates"].update_one(
            {"guild_id": int(guild_id), "nombre": nombre},
            {"$set": {"roles": roles_dict, "guild_id": int(guild_id)}},
            upsert=True
        )
        return redirect(url_for('dashboard', guild_id=guild_id))
    except Exception as e:
        return f"Error al crear la plantilla: {e}", 400

@app.route('/launch_party/<guild_id>', methods=['POST'])
def launch_party(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    
    titulo = request.form.get('titulo')
    descripcion = request.form.get('descripcion')
    plantilla_nombre = request.form.get('plantilla')
    
    db = get_db()
    # Buscamos los roles de la plantilla seleccionada
    temp = db["custom_templates"].find_one({"guild_id": int(guild_id), "nombre": plantilla_nombre})
    
    if not temp:
        return "Plantilla no encontrada", 400

    # Creamos el documento de la party
    # Nota: El _id aquí será un timestamp porque no viene de un mensaje de Discord
    new_party = {
        "_id": int(datetime.now().timestamp()), 
        "guild_id": int(guild_id),
        "creador": "Web Dashboard", # O el ID de Discord del usuario en sesión
        "titulo": titulo,
        "descripcion": descripcion,
        "limites": temp['roles'],
        "participants": {r: [] for r in temp['roles']},
        "banquillo": [],
        "abandonos": [],
        "createdAt": datetime.now(timezone.utc)
    }
    
    db["parties"].insert_one(new_party)
    return redirect(url_for('dashboard', guild_id=guild_id))

@app.route('/plantillas/<guild_id>')
def view_templates(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    db = get_db()
    templates = list(db["custom_templates"].find({"guild_id": int(guild_id)}))
    return render_template('plantillas.html', guild_id=guild_id, templates=templates)

# RUTA: Ver Actividades
@app.route('/ver_actividades/<guild_id>')
def view_activities(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    db = get_db()
    parties = list(db["parties"].find({"guild_id": int(guild_id)}).sort("createdAt", -1))
    return render_template('ver_actividades.html', guild_id=guild_id, parties=parties)

# RUTA: Lanzar Actividad (Actualizada)
@app.route('/launch_party/<guild_id>', methods=['POST'])
def launch_party(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    # ... (Tu lógica anterior de guardar en Mongo) ...
    # Redirigir a ver actividades para ver el resultado
    return redirect(url_for('view_activities', guild_id=guild_id))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)