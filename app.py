import base64
import io
import os
import secrets
import sqlite3
from datetime import datetime
from urllib.parse import urlencode

import qrcode
from flask import Flask, g, redirect, render_template, request, url_for

app = Flask(__name__)
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'data.db')


def get_base_url() -> str:
    env_url = os.environ.get('BASE_URL', '').strip().rstrip('/')
    if env_url:
        return env_url
    return request.host_url.rstrip('/')


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.execute(
        '''
        CREATE TABLE IF NOT EXISTS qr_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target_url TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            random_param TEXT NOT NULL,
            scan_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        '''
    )
    db.execute(
        '''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            qr_id INTEGER NOT NULL,
            scanned_at TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY(qr_id) REFERENCES qr_tokens(id)
        )
        '''
    )
    db.commit()
    db.close()


def make_qr_data_uri(data: str) -> str:
    img = qrcode.make(data)
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    encoded = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return f'data:image/png;base64,{encoded}'


@app.route('/')
def home():
    return redirect(url_for('admin'))


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    db = get_db()
    error = None
    created = None

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        target_url = request.form.get('target_url', '').strip()

        if not name:
            error = 'QR 이름을 입력해 주세요.'
        elif not target_url:
            error = 'URL을 입력해 주세요.'
        elif not (target_url.startswith('http://') or target_url.startswith('https://')):
            error = 'URL은 http:// 또는 https:// 로 시작해야 합니다.'
        else:
            token = secrets.token_urlsafe(12)
            random_param = secrets.token_hex(8)
            created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            db.execute(
                'INSERT INTO qr_tokens (name, target_url, token, random_param, scan_count, created_at) VALUES (?, ?, ?, ?, 0, ?)',
                (name, target_url, token, random_param, created_at)
            )
            db.commit()

            qr_url = f"{get_base_url()}{url_for('scan', token=token)}?{urlencode({'r': random_param})}"
            created = {
                'name': name,
                'target_url': target_url,
                'token': token,
                'random_param': random_param,
                'qr_url': qr_url,
                'qr_image': make_qr_data_uri(qr_url),
            }

    qr_list = db.execute('SELECT * FROM qr_tokens ORDER BY id DESC').fetchall()
    return render_template('admin.html', error=error, created=created, qr_list=qr_list)


@app.route('/scan/<token>')
def scan(token):
    random_param = request.args.get('r', '').strip()
    db = get_db()
    qr = db.execute(
        'SELECT * FROM qr_tokens WHERE token = ? AND random_param = ?',
        (token, random_param)
    ).fetchone()

    if qr is None:
        return render_template('invalid.html'), 404

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', '')

    db.execute(
        'INSERT INTO scan_logs (qr_id, scanned_at, ip_address, user_agent) VALUES (?, ?, ?, ?)',
        (qr['id'], now, ip_address, user_agent)
    )
    db.execute(
        'UPDATE qr_tokens SET scan_count = scan_count + 1 WHERE id = ?',
        (qr['id'],)
    )
    db.commit()

    updated_qr = db.execute('SELECT * FROM qr_tokens WHERE id = ?', (qr['id'],)).fetchone()
    logs = db.execute(
        'SELECT * FROM scan_logs WHERE qr_id = ? ORDER BY id DESC LIMIT 10',
        (qr['id'],)
    ).fetchall()

    if updated_qr['scan_count'] == 1:
        return render_template('authentic.html', qr=updated_qr, logs=logs)
    return render_template('counterfeit.html', qr=updated_qr, logs=logs)


@app.route('/history')
def history():
    db = get_db()
    items = db.execute(
        '''
        SELECT q.id, q.name, q.target_url, q.token, q.random_param, q.scan_count, q.created_at,
               MAX(s.scanned_at) AS last_scanned_at
        FROM qr_tokens q
        LEFT JOIN scan_logs s ON q.id = s.qr_id
        GROUP BY q.id
        ORDER BY q.id DESC
        '''
    ).fetchall()
    return render_template('history.html', items=items, base_url=get_base_url())


if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
else:
    init_db()
