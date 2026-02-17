from flask import Flask, render_template
from pymongo import MongoClient # Usamos la versión sincrónica para evitar líos de loops
import os
from datetime import datetime

app = Flask(__name__)

# Configuración de MongoDB
MONGO_URL = os.getenv('MONGO_URL')

@app.route('/')
def index():
    client = None
    try:
        # Conectamos de forma sincrónica (más estable para una web simple)
        client = MongoClient(MONGO_URL)
        db = client["albion_db"]
        collection_parties = db["parties"]
        
        # Obtenemos las parties ordenadas por fecha
        parties_data = list(collection_parties.find().sort("createdAt", -1).limit(50))
        
        return render_template('index.html', parties=parties_data)
    except Exception as e:
        return f"Error conectando a la base de datos: {e}", 500
    finally:
        if client:
            client.close()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)