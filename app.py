from flask import Flask, render_template, session, redirect, url_for, request, flash
from pymongo import MongoClient
from datetime import datetime, timezone
import os
import requests

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuración de Variables de Entorno
MONGO_URL = os.getenv('MONGO_URL')
CLIENT_ID = os.getenv('DISCORD_CLIENT_ID')
CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
REDIRECT_URI = os.getenv('DISCORD_REDIRECT_URI')
API_ENDPOINT = 'https://discord.com/api/v10'

# --- UTILIDADES ---

def get_db():
    # Se recomienda no crear el cliente en cada llamada, pero para scripts simples:
    client = MongoClient(MONGO_URL)
    return client["albion_db"]

def is_user_admin(guild_id):
    """Verifica si el usuario tiene permiso de Administrador en el servidor."""
    if 'token' not in session: return False
    headers = {'Authorization': f"Bearer {session.get('token')}"}
    r = requests.get(f"{API_ENDPOINT}/users/@me/guilds", headers=headers)
    if r.status_code != 200: return False
    
    for g in r.json():
        if g['id'] == str(guild_id):
            return (int(g['permissions']) & 0x8) == 0x8
    return False

def tiene_permiso_staff(guild_id):
    """Verifica si el usuario tiene el ROL específico de Staff configurado en la DB."""
    if 'token' not in session: return False
    db = get_db()
    
    config = db["config"].find_one({"guild_id": int(guild_id)})
    if not config or "admin_role_id" not in config:
        return False 
    
    admin_role_id = str(config["admin_role_id"])
    headers = {'Authorization': f"Bearer {session['token']}"}
    
    # Pedimos los datos del miembro en ese servidor específico
    r = requests.get(f"{API_ENDPOINT}/users/@me/guilds/{guild_id}/member", headers=headers)
    
    if r.status_code == 200:
        member_data = r.json()
        return admin_role_id in member_data.get("roles", [])
    return False

# --- RUTAS DE NAVEGACIÓN ---

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
    # Filtrar servidores donde soy Admin Y el bot está presente
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
        return "Acceso denegado: Se requieren permisos de Administrador", 403
    
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
        return f"Error en formato de roles: {e}", 400

@app.route('/delete_template/<guild_id>/<template_name>')
def delete_template(guild_id, template_name):
    if 'token' not in session or not is_user_admin(guild_id): return "No autorizado", 403
    
    db = get_db()
    db["custom_templates"].delete_one({"guild_id": int(guild_id), "nombre": template_name})
    return redirect(url_for('view_templates', guild_id=guild_id))

# --- GESTIÓN DE ACTIVIDADES (PARTY) ---

@app.route('/ver_actividades/<guild_id>')
def view_activities(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    db = get_db()
    parties = list(db["parties"].find({"guild_id": int(guild_id)}).sort("createdAt", -1))
    templates = list(db["custom_templates"].find({"guild_id": int(guild_id)}))
    
    # Pasamos si el usuario es STAFF para ver botones de borrar miembros
    es_staff = tiene_permiso_staff(guild_id)
    
    return render_template('ver_actividades.html', 
                           guild_id=guild_id, 
                           parties=parties, 
                           templates=templates, 
                           es_staff=es_staff)

@app.route('/launch_party/<guild_id>', methods=['POST'])
def launch_party_action(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    db = get_db()
    
    # 1. Obtener datos del formulario
    titulo = request.form.get('titulo')
    nombre_plantilla = request.form.get('plantilla')
    descripcion = request.form.get('descripcion') or "Sin descripción"
    
    # 2. Buscar plantilla y CONFIGURACIÓN del servidor
    temp = db["custom_templates"].find_one({"guild_id": int(guild_id), "nombre": nombre_plantilla})
    config = db["config"].find_one({"guild_id": int(guild_id)})
    
    if not temp: return "Plantilla no encontrada", 400

    party_id = int(datetime.now().timestamp())
    
    # 3. Guardar en MongoDB
    new_party = {
        "_id": party_id, 
        "guild_id": int(guild_id),
        "titulo": titulo,
        "descripcion": descripcion,
        "limites": temp['roles'],
        "participants": {r: [] for r in temp['roles']},
        "createdAt": datetime.now(timezone.utc)
    }
    db["parties"].insert_one(new_party)

    # 4. ENVIAR A DISCORD (Si el webhook está configurado)
    if config and config.get("webhook_url"):
        roles_texto = "\n".join([f"🔹 **{r}**: 0/{n}" for r, n in temp['roles'].items()])
        url_web = f"{request.host_url}ver_actividades/{guild_id}"
        
        payload = {
            "embeds": [{
                "title": f"⚔️ ¡NUEVA ACTIVIDAD: {titulo}!",
                "url": url_web,
                "description": f"{descripcion}\n\n**Composición:**\n{roles_texto}\n\n[👉 Pulsa aquí para inscribirte]({url_web})",
                "color": 0x00ff00, # Verde
                "footer": {"text": "Albion Manager - Dashboard Web"},
                "timestamp": datetime.now(timezone.utc).isoformat()
            }]
        }
        try:
            requests.post(config["webhook_url"], json=payload, timeout=5)
        except Exception as e:
            print(f"Error enviando webhook: {e}")

    return redirect(url_for('view_activities', guild_id=guild_id))

@app.route('/remove_member/<guild_id>/<party_id>/<role_name>/<user_id>')
def remove_member(guild_id, party_id, role_name, user_id):
    if not tiene_permiso_staff(guild_id): return "No autorizado", 403
    db = get_db()
    db["parties"].update_one(
        {"_id": int(party_id)},
        {"$pull": {f"participants.{role_name}": {"id": int(user_id)}}}
    )
    return redirect(url_for('view_activities', guild_id=guild_id))

@app.route('/move_member/<guild_id>/<party_id>/<old_role>/<new_role>/<user_id>/<user_name>')
def move_member(guild_id, party_id, old_role, new_role, user_id, user_name):
    if not tiene_permiso_staff(guild_id): return "No autorizado", 403
    db = get_db()
    
    # 1. Sacar del rol viejo
    db["parties"].update_one(
        {"_id": int(party_id)},
        {"$pull": {f"participants.{old_role}": {"id": int(user_id)}}}
    )
    
    # 2. Meter en el rol nuevo
    db["parties"].update_one(
        {"_id": int(party_id)},
        {"$push": {f"participants.{new_role}": {"id": int(user_id), "name": user_name}}}
    )
    return redirect(url_for('view_activities', guild_id=guild_id))

@app.route('/settings/<guild_id>')
def server_settings(guild_id):
    if 'token' not in session or not is_user_admin(guild_id):
        return "No tienes permisos de Administrador", 403
    
    db = get_db()
    # Buscamos si ya existe configuración previa
    config = db["config"].find_one({"guild_id": int(guild_id)})
    return render_template('settings.html', guild_id=guild_id, config=config)

@app.route('/save_settings/<guild_id>', methods=['POST'])
def save_settings(guild_id):
    if 'token' not in session or not is_user_admin(guild_id):
        return "No autorizado", 403
    
    db = get_db()
    webhook_url = request.form.get('webhook_url')
    admin_role_id = request.form.get('admin_role_id')
    
    # Guardamos o actualizamos la config de ESTE servidor
    db["config"].update_one(
        {"guild_id": int(guild_id)},
        {"$set": {
            "webhook_url": webhook_url,
            "admin_role_id": admin_role_id
        }},
        upsert=True
    )
    flash("Configuración guardada correctamente")
    return redirect(url_for('server_settings', guild_id=guild_id))

# --- AUTH DISCORD ---

@app.route('/login')
def login():
    auth_url = f"https://discord.com/api/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope=identify+guilds+guilds.members.read"
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