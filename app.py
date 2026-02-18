from flask import Flask, render_template, request, redirect, url_for, session
from bson.objectid import ObjectId
from flask import Flask, render_template, session, redirect, url_for, request, flash
from pymongo import MongoClient
from datetime import datetime, timezone
import os
import requests

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- CONFIGURACIÓN DE VARIABLES DE ENTORNO ---
MONGO_URL = os.getenv('MONGO_URL')
CLIENT_ID = os.getenv('DISCORD_CLIENT_ID')
CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
REDIRECT_URI = os.getenv('DISCORD_REDIRECT_URI')
BOT_TOKEN = os.getenv('DISCORD_TOKEN')
API_ENDPOINT = 'https://discord.com/api/v10'

# --- CONEXIÓN PERSISTENTE A MONGO ---
client = MongoClient(MONGO_URL)
db = client["albion_db"]

# --- UTILIDADES DE PERMISOS ---

def is_user_admin(guild_id):
    """Verifica si el usuario tiene el permiso de ADMINISTRATOR en el servidor."""
    if 'token' not in session: return False
    headers = {'Authorization': f"Bearer {session.get('token')}"}
    r = requests.get(f"{API_ENDPOINT}/users/@me/guilds", headers=headers)
    if r.status_code != 200: return False
    
    for g in r.json():
        if g['id'] == str(guild_id):
            return (int(g['permissions']) & 0x8) == 0x8
    return False

def tiene_permiso_staff(guild_id):
    """Verifica si es Admin o si tiene el Rol de Staff configurado en la DB."""
    if 'token' not in session: return False
    config = db["server_config"].find_one({"guild_id": int(guild_id)})
    headers = {'Authorization': f"Bearer {session['token']}"}

    # 1. Verificar si es Administrador o Dueño
    r_guilds = requests.get(f"{API_ENDPOINT}/users/@me/guilds", headers=headers)
    if r_guilds.status_code == 200:
        for g in r_guilds.json():
            if g['id'] == str(guild_id) and (int(g['permissions']) & 0x8) == 0x8:
                return True

    # 2. Verificar si tiene el rol específico guardado en la config
    if config and "role_id" in config:
        r_mem = requests.get(f"{API_ENDPOINT}/users/@me/guilds/{guild_id}/member", headers=headers)
        if r_mem.status_code == 200:
            roles_usuario = [str(r) for r in r_mem.json().get("roles", [])]
            return str(config["role_id"]) in roles_usuario
            
    return False

# --- RUTAS DE NAVEGACIÓN PRINCIPAL ---

@app.route('/')
def index():
    bot_info = requests.get(f"{API_ENDPOINT}/users/@me", headers={'Authorization': f"Bot {BOT_TOKEN}"}).json()
    bot_avatar_url = f"https://cdn.discordapp.com/avatars/{bot_info['id']}/{bot_info['avatar']}.png"
    if 'token' not in session:
        return render_template('login.html')
    
    headers = {'Authorization': f"Bearer {session['token']}"}
    user_guilds_resp = requests.get(f"{API_ENDPOINT}/users/@me/guilds", headers=headers)
    
    if user_guilds_resp.status_code != 200:
        session.clear()
        return redirect(url_for('index'))

    user_guilds = user_guilds_resp.json()
    bot_headers = {'Authorization': f"Bot {BOT_TOKEN}"}
    bot_guilds_resp = requests.get(f"{API_ENDPOINT}/users/@me/guilds", headers=bot_headers).json()
    
    if isinstance(bot_guilds_resp, dict) and "message" in bot_guilds_resp:
        return f"Error de Discord API: {bot_guilds_resp['message']}", 500

    bot_guild_ids = [g['id'] for g in bot_guilds_resp]
    final_guilds = [g for g in user_guilds if (int(g['permissions']) & 0x8) == 0x8 and g['id'] in bot_guild_ids]

    return render_template('select_server.html', guilds=final_guilds, bot_avatar=bot_avatar_url)

@app.route('/dashboard/<guild_id>')
def server_dashboard(guild_id):
    if 'token' not in session: 
        return redirect(url_for('index'))
    
    # Aquí deberías obtener el nombre del servidor de tu lista de guilds
    # Ejemplo rápido si tienes la info en sesión o db:
    guild_name = "Nombre de tu Gremio" # Reemplazar por la lógica que obtiene el nombre
    
    return render_template('index.html', guild_id=guild_id, guild_name=guild_name)

# --- GESTIÓN DE PLANTILLAS ---

@app.route('/plantillas/<guild_id>')
def view_templates(guild_id):
    if 'token' not in session or not is_user_admin(guild_id):
        return "Acceso denegado", 403
    templates = list(db["custom_templates"].find({"guild_id": int(guild_id)}))
    return render_template('plantillas.html', guild_id=guild_id, templates=templates)

@app.route('/create_template/<guild_id>', methods=['POST'])
def create_template_action(guild_id):
    if 'token' not in session or not is_user_admin(guild_id): return "No autorizado", 403
    nombre = request.form.get('nombre')
    roles_input = request.form.get('roles')
    try:
        roles_dict = {p.split(':')[0].strip(): int(p.split(':')[1].strip()) for p in roles_input.split(',') if ':' in p}
        db["custom_templates"].update_one(
            {"guild_id": int(guild_id), "nombre": nombre},
            {"$set": {"roles": roles_dict, "guild_id": int(guild_id)}},
            upsert=True
        )
        flash(f"Plantilla '{nombre}' guardada.")
        return redirect(url_for('view_templates', guild_id=guild_id))
    except Exception as e:
        return f"Error en formato de roles: {e}", 400

# --- GESTIÓN DE ACTIVIDADES (PARTIES) ---

@app.route('/ver_actividades/<guild_id>')
def view_activities(guild_id):
    if 'token' not in session: return redirect(url_for('index'))
    
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
    
    titulo = request.form.get('titulo')
    nombre_plantilla = request.form.get('plantilla')
    descripcion = request.form.get('descripcion') or "Sin descripción"
    
    # 1. Obtener roles
    db_temp = db["custom_templates"].find_one({"guild_id": int(guild_id), "nombre": nombre_plantilla})
    if db_temp:
        temp_roles = db_temp['roles']
    else:
        fijas = {
            "Ganking": {"Dps": 5, "Tank": 1, "Healer": 1}, 
            "HCE": {"Tank": 1, "Healer": 1, "Dps": 3}, 
            "ZVZ": {"Tank": 5, "Healer": 5, "Dps": 15}
        }
        temp_roles = fijas.get(nombre_plantilla)

    if not temp_roles: return "Plantilla no encontrada", 400

    config = db["server_config"].find_one({"guild_id": int(guild_id)})
    if not config or not config.get("channel_id"):
        return "Canal no configurado.", 400

    # 2. Mapeo de Emojis para botones
    role_emojis = {
        "Tank": "🛡️", "Main Tank": "🛡️", "Off Tank": "🛡️",
        "Healer": "❤️", "Dps": "⚔️", "Melee": "⚔️", 
        "Ranged": "🏹", "Support": "✨"
    }

    # 3. Enviar mensaje inicial
    url = f"{API_ENDPOINT}/channels/{config['channel_id']}/messages"
    headers = {"Authorization": f"Bot {BOT_TOKEN}", "Content-Type": "application/json"}
    
    payload_inicial = {
        "embeds": [{
            "title": f"⚔️ {titulo}",
            "description": f"{descripcion}\n\n📌 **Líder:** Dashboard",
            "color": 0xFFD700,
            "fields": [{"name": f"{r} (0/{n})", "value": "Vacío", "inline": True} for r, n in temp_roles.items()]
        }]
    }
    
    resp = requests.post(url, headers=headers, json=payload_inicial)
    if resp.status_code != 200: return f"Error Discord: {resp.text}", 500
    
    discord_msg = resp.json()
    real_msg_id = int(discord_msg['id']) 

    # 4. Guardar en MongoDB
    new_party = {
        "_id": real_msg_id, 
        "guild_id": int(guild_id),
        "creador": "Dashboard",
        "titulo": titulo, "descripcion": descripcion,
        "channel_id": int(config['channel_id']),
        "limites": temp_roles, 
        "participants": {r: [] for r in temp_roles},
        "banquillo": [], "abandonos_info": [], 
        "createdAt": datetime.now(timezone.utc)
    }
    db["parties"].insert_one(new_party)

    # 5. Generar Componentes (Botones) corregidos
    components = []
    all_roles = list(temp_roles.keys())
    
    # Filas de Roles
    for i in range(0, len(all_roles), 5):
        chunk = all_roles[i:i+5]
        components.append({
            "type": 1,
            "components": [
                {
                    "type": 2, "style": 2, "label": r, 
                    "emoji": {"name": role_emojis.get(r, "👤")},
                    "custom_id": f"role_{r}_{real_msg_id}"
                } for r in chunk
            ]
        })

    # Fila de Utilidades
    components.append({
        "type": 1,
        "components": [
            {"type": 2, "style": 2, "label": "Banquillo", "emoji": {"name": "🛋️"}, "custom_id": f"bench_{real_msg_id}"},
            {"type": 2, "style": 4, "label": "Salirse", "emoji": {"name": "❌"}, "custom_id": f"leave_{real_msg_id}"}
        ]
    })

    # Fila de Gestión Staff
    components.append({
        "type": 1,
        "components": [
            {"type": 2, "style": 2, "label": "Gestionar", "emoji": {"name": "⚙️"}, "custom_id": f"manage_{real_msg_id}"},
            {"type": 2, "style": 1, "label": "Avisar", "emoji": {"name": "🔔"}, "custom_id": f"notify_{real_msg_id}"},
            {"type": 2, "style": 4, "label": "Borrar", "emoji": {"name": "🗑️"}, "custom_id": f"delete_{real_msg_id}"}
        ]
    })

    requests.patch(f"{url}/{real_msg_id}", headers=headers, json={"components": components})

    flash("¡Party lanzada con éxito!")
    return redirect(url_for('view_activities', guild_id=guild_id))

# --- CONFIGURACIÓN DEL SERVIDOR ---

@app.route('/settings/<guild_id>')
def server_settings(guild_id):
    if 'token' not in session or not is_user_admin(guild_id): return "No autorizado", 403
    config = db["server_config"].find_one({"guild_id": int(guild_id)})
    return render_template('settings.html', guild_id=guild_id, config=config)

@app.route('/save_settings/<guild_id>', methods=['POST'])
def save_settings(guild_id):
    if 'token' not in session or not is_user_admin(guild_id): return "No autorizado", 403
    
    try:
        db["server_config"].update_one(
            {"guild_id": int(guild_id)},
            {"$set": {
                "channel_id": int(request.form.get('channel_id')),
                "role_id": int(request.form.get('admin_role_id')),
                "webhook_url": request.form.get('webhook_url')
            }},
            upsert=True
        )
        flash("Configuración guardada.")
    except:
        flash("Error: Los IDs deben ser números.")
        
    return redirect(url_for('server_settings', guild_id=guild_id))

# --- AUTENTICACIÓN OAUTH2 ---

# --- RUTA PARA GUARDAR/CREAR PLANTILLAS ---
@app.route('/create_template/<guild_id>', methods=['POST'])
def create_template(guild_id):
    nombre = request.form.get('nombre')
    roles_input = request.form.get('roles') # Formato "Tanque:2, Healer:4"
    
    # Convertimos el texto en un diccionario real
    roles_dict = {}
    try:
        for item in roles_input.split(','):
            partes = item.split(':')
            roles_dict[partes[0].strip()] = int(partes[1].strip())
        
        # Guardamos o actualizamos en la DB
        db.templates.update_one(
            {"guild_id": guild_id, "nombre": nombre},
            {"$set": {"roles": roles_dict}},
            upsert=True
        )
    except Exception as e:
        print(f"Error al procesar roles: {e}")
        
    return redirect(url_for('ver_plantillas', guild_id=guild_id))

# --- RUTA PARA LANZAR ACTIVIDAD (Copia la plantilla) ---
@app.route('/lanzar_actividad/<guild_id>', methods=['POST'])
def lanzar_actividad(guild_id):
    titulo = request.form.get('titulo')
    nombre_plantilla = request.form.get('plantilla_id') # <--- Cambiado para que coincida con el HTML
    
    # Buscamos en la colección de plantillas personalizadas
    plantilla = db["custom_templates"].find_one({"guild_id": int(guild_id), "nombre": nombre_plantilla})
    
    # Si no existe, usamos una por defecto (Ganking)
    roles = plantilla['roles'] if plantilla else {"Dps": 5, "Tank": 1, "Healer": 1}

    nueva_party = {
        "guild_id": int(guild_id),
        "titulo": titulo,
        "creador": session.get('user_name', 'Admin'),
        "limites": roles,
        "participants": {rol: [] for rol in roles.keys()}, # Inicializa los roles vacíos
        "createdAt": datetime.now(timezone.utc)
    }
    db["parties"].insert_one(nueva_party) # <--- Guardamos en "parties"
    return redirect(url_for('view_activities', guild_id=guild_id))

# --- RUTA PARA EL BOTÓN "UNIRSE" ---
@app.route('/unirse/<guild_id>/<party_id>/<role>')
def unirse(guild_id, party_id, role):
    user_name = session.get('user_name', 'Usuario Web')
    
    # IMPORTANTE: Quitamos ObjectId() y usamos int() porque el ID de Discord es un número
    db["parties"].update_one(
        {"_id": int(party_id)}, 
        {"$addToSet": {f"participants.{role}": user_name}}
    )
    return redirect(url_for('view_activities', guild_id=guild_id))

@app.route('/borrar_actividad/<guild_id>/<party_id>', methods=['POST'])
def borrar_actividad(guild_id, party_id):
    # IMPORTANTE: Quitamos ObjectId() y usamos int()
    db["parties"].delete_one({"_id": int(party_id)})
    flash("Actividad eliminada.")
    return redirect(url_for('view_activities', guild_id=guild_id))

@app.route('/login')
def login():
    auth_url = f"https://discord.com/api/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope=identify+guilds+guilds.members.read"
    return redirect(auth_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    data = {
        'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code', 'code': code, 'redirect_uri': REDIRECT_URI
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
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))