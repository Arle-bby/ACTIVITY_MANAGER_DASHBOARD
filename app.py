from flask import Flask, render_template
from motor.motor_asyncio import AsyncIOMotorClient
import os
import asyncio
from datetime import datetime

app = Flask(__name__)

# Configuración de MongoDB (Usa la misma URL que en Railway)
MONGO_URL = os.getenv('MONGO_URL')
cluster = AsyncIOMotorClient(MONGO_URL)
db = cluster["albion_db"]
collection_parties = db["parties"]

@app.route('/')
def index():
    # Usamos una pequeña función para ejecutar la consulta asíncrona
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    async def get_data():
        cursor = collection_parties.find().sort("createdAt", -1)
        return await cursor.to_list(length=50)

    parties_data = loop.run_until_complete(get_data())
    return render_template('index.html', parties=parties_data)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)