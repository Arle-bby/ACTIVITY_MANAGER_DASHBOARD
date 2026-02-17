from flask import Flask, render_template
from motor.motor_asyncio import AsyncIOMotorClient
import os
import asyncio
from datetime import datetime

app = Flask(__name__)

# Configuración de MongoDB
MONGO_URL = os.getenv('MONGO_URL')
# Creamos el cliente fuera para que sea global
cluster = AsyncIOMotorClient(MONGO_URL)
db = cluster["albion_db"]
collection_parties = db["parties"]

@app.route('/')
def index():
    try:
        # Forma simplificada de obtener datos en Flask
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        cursor = collection_parties.find().sort("createdAt", -1)
        parties_data = loop.run_until_complete(cursor.to_list(length=50))
        loop.close()
        
        return render_template('index.html', parties=parties_data)
    except Exception as e:
        return f"Error conectando a la base de datos: {e}", 500

if __name__ == "__main__":
    # Render usa el puerto 10000 por defecto
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)