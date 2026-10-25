"""Local development entry point. Production uses Gunicorn (app:app)."""
import os
from dotenv import load_dotenv
from app import app

load_dotenv()

if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "False").lower() in ("1", "true")
    port = int(os.getenv("PORT", "5000"))
    app.run(debug=debug, host="127.0.0.1", port=port)
