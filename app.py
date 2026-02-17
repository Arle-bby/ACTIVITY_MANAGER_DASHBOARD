from flask import Flask, render_template, session, redirect, url_for, request, flash
from pymongo import MongoClient
from datetime import datetime, timezone
import os
import requests

app = Flask(__name__)
app.secret_key = os.urandom(24)

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
    user_guilds = requests.get(f"{API_ENDPOINT}/users/@me/guilds", headers=headers).json()
    
    bot_token = os.getenv('DISCORD_TOKEN')
    bot_headers = {'Authorization': f"Bot {bot_token}"}
    bot_guilds_resp = requests.get(f"{API_ENDPOINT}/users/@me/guilds", headers=bot_headers).json()
    
    if isinstance(bot_guilds_resp, dict) and "message" in bot_guilds_resp:
        return f"Error de Discord API: {bot_guilds_resp['message']}", 500

    bot_guild_ids = [g['id'] for g in bot_guilds_resp]
    final_guilds = [g for g in user_guilds if (int(g['permissions']) & 0x8) == 0x8 and g['id'] in bot_guild_ids]
            
    return render_template('select_server.html', guilds=final_guilds)

@app.route('/dashboard/<guild_id>')
def server_dashboard(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    # Esta es la página principal del servidor (el menú de 3 botones)
    return render_template('index.html', guild_id=guild_id)

@app.route('/plantillas/<guild_id>')
def view_templates(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    db = get_db()
    templates = list(db["custom_templates"].find({"guild_id": int(guild_id)}))
    return render_template('plantillas.html', guild_id=guild_id, templates=templates)

@app.route('/ver_actividades/<guild_id>')
def view_activities(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    db = get_db()
    parties = list(db["parties"].find({"guild_id": int(guild_id)}).sort("createdAt", -1))
    # Obtenemos plantillas también para el modal de "Lanzar" que está en esta página
    templates = list(db["custom_templates"].find({"guild_id": int(guild_id)}))
    return render_template('ver_actividades.html', guild_id=guild_id, parties=parties, templates=templates)

@app.route('/create_template/<guild_id>', methods=['POST'])
def create_template_action(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    nombre = request.form.get('nombre')
    roles_input = request.form.get('roles')
    
    try:
        roles_dict = {p.split(':')[0].strip(): int(p.split(':')[1].strip()) for p in roles_input.split(',') if ':' in p}
        db = get_db()
        db["custom_templates"].update_one(
            {"guild_id": int(guild_id), "nombre": nombre},
            {"$set": {"roles": roles_dict, "guild_id": int(guild_id)}},
            upsert=True
        )
        return redirect(url_for('view_templates', guild_id=guild_id))
    except Exception as e:
        return f"Error: {e}", 400

@app.route('/launch_party/<guild_id>', methods=['POST'])
def launch_party_action(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    db = get_db()
    temp = db["custom_templates"].find_one({"guild_id": int(guild_id), "nombre": request.form.get('plantilla')})
    
    if temp:
        new_party = {
            "_id": int(datetime.now().timestamp()), 
            "guild_id": int(guild_id),
            "creador": "Web",
            "titulo": request.form.get('titulo'),
            "descripcion": request.form.get('descripcion'),
            "limites": temp['roles'],
            "participants": {r: [] for r in temp['roles']},
            "banquillo": [],
            "abandonos": [],
            "createdAt": datetime.now(timezone.utc)
        }
        db["parties"].insert_one(new_party)
    return redirect(url_for('view_activities', guild_id=guild_id))

@app.route('/login')
def login():
    auth_url = f"https://discord.com/api/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope=identify+guilds"
    return redirect(auth_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    data = {'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET, 'grant_type': 'authorization_code', 'code': code, 'redirect_uri': REDIRECT_URI}
    r = requests.post(f"{API_ENDPOINT}/oauth2/token", data=data)
    session['token'] = r.json().get('access_token')
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)