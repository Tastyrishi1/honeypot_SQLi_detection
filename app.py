from flask import Flask, request
import sqlite3
from datetime import datetime

app = Flask(__name__)
LOG_DB = 'logs.db'


def init_db():
    conn = sqlite3.connect(LOG_DB)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS injection_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            user_agent TEXT,
            payload TEXT
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/search')
def search():
    query = request.args.get('q', '')
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')

    conn = sqlite3.connect(LOG_DB)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO injection_logs (timestamp, ip, user_agent, payload) VALUES (?, ?, ?, ?)",
                   (datetime.utcnow().isoformat(), ip, user_agent, query))
    conn.commit()
    conn.close()

    sqli_signs = ["'", '"', '--', ';', '/*', '*/', ' or ', ' and ', '1=1', 'union', 'select']
    if any(sign in query.lower() for sign in sqli_signs):
        return "500 Internal Server Error - SQL syntax error", 500
    return f"0 results for '{query}'"

if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=8080)
