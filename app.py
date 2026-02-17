from flask import Flask, render_template, session, redirect, url_for, request
from pymongo import MongoClient
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
    # Servidores del usuario
    user_guilds = requests.get("https://discord.com/api/v10/users/@me/guilds", headers=headers).json()
    
    # Servidores del BOT (necesitas el BOT_TOKEN en tus variables de entorno)
    bot_headers = {'Authorization': f"Bot {os.getenv('DISCORD_TOKEN')}"}
    bot_guilds_resp = requests.get("https://discord.com/api/v10/users/@me/guilds", headers=bot_headers).json()
    bot_guild_ids = [g['id'] for g in bot_guilds_resp]
    
    # Filtrar: Que el usuario sea Admin Y que el bot esté en el server
    final_guilds = []
    for g in user_guilds:
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)