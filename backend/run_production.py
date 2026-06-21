import os
from app import app, socketio

if __name__ == '__main__':
    # Dynamically bind to the PORT environment variable assigned by the hosting provider (default to 5000)
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting production server on port {port}...")
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
