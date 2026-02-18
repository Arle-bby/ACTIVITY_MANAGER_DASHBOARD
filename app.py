from flask import Flask, render_template, session, redirect, url_for, request, flash
from pymongo import MongoClient
from datetime import datetime, timezone
import os
import requests

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- CONFIGURACIÓN ---
MONGO_URL = os.getenv('MONGO_URL')
CLIENT_ID = os.getenv('DISCORD_CLIENT_ID')
CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
REDIRECT_URI = os.getenv('DISCORD_REDIRECT_URI')
BOT_TOKEN = os.getenv('DISCORD_TOKEN')
API_ENDPOINT = 'https://discord.com/api/v10'

# --- UTILIDADES ---

def get_db():
    client = MongoClient(MONGO_URL)
    return client["albion_db"]

def is_user_admin(guild_id):
    """Verifica permisos de administrador del usuario en Discord."""
    if 'token' not in session: return False
    headers = {'Authorization': f"Bearer {session.get('token')}"}
    r = requests.get(f"{API_ENDPOINT}/users/@me/guilds", headers=headers)
    if r.status_code != 200: return False
    
    for g in r.json():
        if g['id'] == str(guild_id):
            return (int(g['permissions']) & 0x8) == 0x8
    return False

def tiene_permiso_staff(guild_id):
    """Verifica si el usuario es staff según la configuración del bot."""
    if 'token' not in session: return False
    db = get_db()
    config = db["server_config"].find_one({"guild_id": int(guild_id)})
    headers = {'Authorization': f"Bearer {session['token']}"}

    # Dueño o Admin
    r_guilds = requests.get(f"{API_ENDPOINT}/users/@me/guilds", headers=headers)
    if r_guilds.status_code == 200:
        for g in r_guilds.json():
            if g['id'] == str(guild_id) and (int(g['permissions']) & 0x8) == 0x8:
                return True

    # Rol de Staff configurado
    if config and "admin_role_id" in config:
        r_mem = requests.get(f"{API_ENDPOINT}/users/@me/guilds/{guild_id}/member", headers=headers)
        if r_mem.status_code == 200:
            roles = [str(r) for r in r_mem.json().get("roles", [])]
            return str(config["admin_role_id"]) in roles
            
    return False

# --- RUTAS DE NAVEGACIÓN ---

@app.route('/')
def index():
    if 'token' not in session:
        return render_template('login.html')
    
    headers = {'Authorization': f"Bearer {session['token']}"}
    user_guilds = requests.get(f"{API_ENDPOINT}/users/@me/guilds", headers=headers).json()
    
    bot_headers = {'Authorization': f"Bot {BOT_TOKEN}"}
    bot_guilds_resp = requests.get(f"{API_ENDPOINT}/users/@me/guilds", headers=bot_headers).json()
    
    if isinstance(bot_guilds_resp, dict) and "message" in bot_guilds_resp:
        return f"Error de Discord API: {bot_guilds_resp['message']}", 500

    bot_guild_ids = [g['id'] for g in bot_guilds_resp]
    final_guilds = [g for g in user_guilds if (int(g['permissions']) & 0x8) == 0x8 and g['id'] in bot_guild_ids]
            
    return render_template('select_server.html', guilds=final_guilds)

@app.route('/dashboard/<guild_id>')
def server_dashboard(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    return render_template('index.html', guild_id=guild_id)

# --- GESTIÓN DE PLANTILLAS ---

@app.route('/plantillas/<guild_id>')
def view_templates(guild_id):
    if 'token' not in session or not is_user_admin(guild_id):
        return "Acceso denegado", 403
    db = get_db()
    templates = list(db["custom_templates"].find({"guild_id": int(guild_id)}))
    return render_template('plantillas.html', guild_id=guild_id, templates=templates)

@app.route('/create_template/<guild_id>', methods=['POST'])
def create_template_action(guild_id):
    if 'token' not in session or not is_user_admin(guild_id): return "No autorizado", 403
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

@app.route('/delete_template/<guild_id>/<template_name>')
def delete_template(guild_id, template_name):
    if 'token' not in session or not is_user_admin(guild_id): return "No autorizado", 403
    db = get_db()
    db["custom_templates"].delete_one({"guild_id": int(guild_id), "nombre": template_name})
    return redirect(url_for('view_templates', guild_id=guild_id))

# --- GESTIÓN DE ACTIVIDADES ---

@app.route('/ver_actividades/<guild_id>')
def view_activities(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    db = get_db()
    
    # Combinar Plantillas Fijas + DB
    db_templates = list(db["custom_templates"].find({"guild_id": int(guild_id)}))
    fixed_templates = [
        {"nombre": "Ganking", "roles": {"Dps": 5, "Tank": 1, "Healer": 1}},
        {"nombre": "HCE", "roles": {"Tank": 1, "Healer": 1, "Dps": 3}},
        {"nombre": "ZVZ", "roles": {"Tank": 5, "Healer": 5, "Dps": 15}}
    ]
    all_templates = fixed_templates + [{"nombre": t["nombre"], "roles": t["roles"]} for t in db_templates]
    
    parties = list(db["parties"].find({"guild_id": int(guild_id)}).sort("createdAt", -1))
    es_staff = tiene_permiso_staff(guild_id)
    
    return render_template('ver_actividades.html', 
                           guild_id=guild_id, 
                           parties=parties, 
                           templates=all_templates, 
                           es_staff=es_staff)

@app.route('/launch_party/<guild_id>', methods=['POST'])
def launch_party_action(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    db = get_db()
    
    titulo = request.form.get('titulo')
    nombre_plantilla = request.form.get('plantilla')
    descripcion = request.form.get('descripcion') or "Sin descripción"
    
    # 1. Buscar roles de la plantilla
    db_temp = db["custom_templates"].find_one({"guild_id": int(guild_id), "nombre": nombre_plantilla})
    if db_temp:
        temp_roles = db_temp['roles']
    else:
        fijas = {"Ganking": {"Dps": 5, "Tank": 1, "Healer": 1}, "HCE": {"Tank": 1, "Healer": 1, "Dps": 3}, "ZVZ": {"Tank": 5, "Healer": 5, "Dps": 15}}
        temp_roles = fijas.get(nombre_plantilla)

    if not temp_roles: return "Plantilla no encontrada", 400

    # 2. Guardar en DB
    party_id = int(datetime.now().timestamp())
    new_party = {
        "_id": party_id, 
        "guild_id": int(guild_id),
        "titulo": titulo, "descripcion": descripcion,
        "limites": temp_roles, "participants": {r: [] for r in temp_roles},
        "banquillo": [], "abandonos": [], "createdAt": datetime.now(timezone.utc)
    }
    db["parties"].insert_one(new_party)

    # 3. Enviar a Discord como el Bot
    config = db["server_config"].find_one({"guild_id": int(guild_id)})
    if config and config.get("channel_id"):
        url = f"https://discord.com/api/v10/channels/{config['channel_id']}/messages"
        headers = {"Authorization": f"Bot {BOT_TOKEN}", "Content-Type": "application/json"}
        
        # Botones de Roles
        btns_roles = [{"type": 2, "style": 1, "label": r, "custom_id": f"join_{party_id}_{r}"} for r in temp_roles.keys()]
        # Botones de Gestión
        btns_gest = [
            {"type": 2, "style": 2, "label": "Gestionar", "custom_id": f"manage_{party_id}"},
            {"type": 2, "style": 3, "label": "Avisar", "custom_id": f"notify_{party_id}"},
            {"type": 2, "style": 4, "label": "Borrar", "custom_id": f"delete_{party_id}"},
            {"type": 2, "style": 2, "label": "Banquillo", "custom_id": f"bench_{party_id}"},
            {"type": 2, "style": 4, "label": "Salirse", "custom_id": f"leave_{party_id}"}
        ]

        payload = {
            "embeds": [{
                "title": f"⚔️ {titulo}",
                "description": f"{descripcion}\n\n📌 **Líder:** Dashboard",
                "color": 0xFFD700,
                "fields": [{"name": f"{r} (0/{n})", "value": "Vacío", "inline": True} for r, n in temp_roles.items()]
            }],
            "components": [{"type": 1, "components": btns_roles[:5]}, {"type": 1, "components": btns_gest}]
        }
        requests.post(url, headers=headers, json=payload)

    return redirect(url_for('view_activities', guild_id=guild_id))

# --- CONFIGURACIÓN DEL SERVIDOR ---

@app.route('/settings/<guild_id>')
def server_settings(guild_id):
    if 'token' not in session or not is_user_admin(guild_id): return "No autorizado", 403
    db = get_db()
    config = db["server_config"].find_one({"guild_id": int(guild_id)})
    return render_template('settings.html', guild_id=guild_id, config=config)

@app.route('/save_settings/<guild_id>', methods=['POST'])
def save_settings(guild_id):
    if 'token' not in session or not is_user_admin(guild_id): return "No autorizado", 403
    db = get_db()
    db["server_config"].update_one(
        {"guild_id": int(guild_id)},
        {"$set": {"webhook_url": request.form.get('webhook_url'), "admin_role_id": request.form.get('admin_role_id')}},
        upsert=True
    )
    flash("Configuración guardada")
    return redirect(url_for('server_settings', guild_id=guild_id))

# --- AUTH DISCORD ---

@app.route('/login')
def login():
    auth_url = f"https://discord.com/api/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope=identify+guilds+guilds.members.read"
    return redirect(auth_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    data = {'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET, 'grant_type': 'authorization_code', 'code': code, 'redirect_uri': REDIRECT_URI}
    r = requests.post(f"{API_ENDPOINT}/oauth2/token", data=data)
    token_data = r.json()
    if 'access_token' in token_data:
        session['token'] = token_data['access_token']
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)