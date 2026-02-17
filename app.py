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
        return render_template('login.html') # Una página simple con un botón de Login
    
    # Obtener servidores del usuario
    headers = {'Authorization': f"Bearer {session['token']}"}
    user_guilds = requests.get(f"{API_ENDPOINT}/users/@me/guilds", headers=headers).json()
    
    # Filtrar solo servidores donde es Admin (Permissions & 0x8)
    admin_guilds = [g for g in user_guilds if (int(g['permissions']) & 0x8) == 0x8]
    
    return render_template('select_server.html', guilds=admin_guilds)

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