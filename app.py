import base64
import csv
import io
import os
import secrets
import sqlite3
import zipfile
from datetime import datetime
from urllib.parse import urlencode

import qrcode
from flask import Flask, g, redirect, render_template, request, url_for, send_file

app = Flask(__name__)
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'data.db')


def get_base_url() -> str:
    env_url = os.environ.get('BASE_URL', '').strip().rstrip('/')
    if env_url:
        return env_url
    return request.host_url.rstrip('/')


def build_qr_url(token: str, random_param: str) -> str:
    return f"{get_base_url()}{url_for('scan', token=token)}?{urlencode({'r': random_param})}"


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


def make_qr_png_bytes(data: str) -> bytes:
    img = qrcode.make(data)
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    return buffer.getvalue()


def make_qr_data_uri(data: str) -> str:
    encoded = base64.b64encode(make_qr_png_bytes(data)).decode('utf-8')
    return f'data:image/png;base64,{encoded}'


def safe_file_name(value: str) -> str:
    cleaned = ''.join(ch if ch.isalnum() or ch in ('-', '_') else '_' for ch in value.strip())
    return cleaned[:80] or 'qr'


def fetch_qr_items(selected_ids=None):
    db = get_db()
    if selected_ids:
        placeholders = ','.join('?' for _ in selected_ids)
        query = f'''
            SELECT q.id, q.name, q.target_url, q.token, q.random_param, q.scan_count, q.created_at,
                   MAX(s.scanned_at) AS last_scanned_at
            FROM qr_tokens q
            LEFT JOIN scan_logs s ON q.id = s.qr_id
            WHERE q.id IN ({placeholders})
            GROUP BY q.id
            ORDER BY q.id DESC
        '''
        return db.execute(query, selected_ids).fetchall()

    return db.execute(
        '''
        SELECT q.id, q.name, q.target_url, q.token, q.random_param, q.scan_count, q.created_at,
               MAX(s.scanned_at) AS last_scanned_at
        FROM qr_tokens q
        LEFT JOIN scan_logs s ON q.id = s.qr_id
        GROUP BY q.id
        ORDER BY q.id DESC
        '''
    ).fetchall()


def build_qr_download_zip(items):
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        csv_buffer = io.StringIO()
        writer = csv.writer(csv_buffer)
        writer.writerow(['id', 'name', 'target_url', 'scan_count', 'created_at', 'last_scanned_at', 'scan_url'])

        for item in items:
            qr_url = build_qr_url(item['token'], item['random_param'])
            file_stem = f"{item['id']:03d}_{safe_file_name(item['name'])}"
            zf.writestr(f"qr_codes/{file_stem}.png", make_qr_png_bytes(qr_url))
            writer.writerow([
                item['id'], item['name'], item['target_url'], item['scan_count'],
                item['created_at'], item['last_scanned_at'] or '', qr_url
            ])

        zf.writestr('qr_codes_manifest.csv', csv_buffer.getvalue().encode('utf-8-sig'))

    memory_file.seek(0)
    return memory_file


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

            qr_url = build_qr_url(token, random_param)
            created = {
                'name': name,
                'target_url': target_url,
                'token': token,
                'random_param': random_param,
                'qr_url': qr_url,
                'qr_image': make_qr_data_uri(qr_url),
            }

    qr_rows = db.execute('SELECT * FROM qr_tokens ORDER BY id DESC').fetchall()
    qr_list = []
    for item in qr_rows:
        qr_url = build_qr_url(item['token'], item['random_param'])
        qr_list.append({
            'id': item['id'],
            'name': item['name'],
            'target_url': item['target_url'],
            'scan_count': item['scan_count'],
            'created_at': item['created_at'],
            'qr_url': qr_url,
        })
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
    items = fetch_qr_items()
    enriched = []
    for item in items:
        enriched.append({
            'id': item['id'],
            'name': item['name'],
            'target_url': item['target_url'],
            'token': item['token'],
            'random_param': item['random_param'],
            'scan_count': item['scan_count'],
            'created_at': item['created_at'],
            'last_scanned_at': item['last_scanned_at'],
            'scan_url': build_qr_url(item['token'], item['random_param']),
            'download_url': url_for('download_qr_png', qr_id=item['id']),
        })
    return render_template('history.html', items=enriched)


@app.route('/download/qr/<int:qr_id>.png')
def download_qr_png(qr_id):
    db = get_db()
    item = db.execute('SELECT * FROM qr_tokens WHERE id = ?', (qr_id,)).fetchone()
    if item is None:
        return render_template('invalid.html'), 404

    qr_url = build_qr_url(item['token'], item['random_param'])
    image_bytes = io.BytesIO(make_qr_png_bytes(qr_url))
    filename = f"qr_{item['id']:03d}_{safe_file_name(item['name'])}.png"
    return send_file(image_bytes, mimetype='image/png', as_attachment=True, download_name=filename)


@app.route('/download/all')
def download_all():
    items = fetch_qr_items()
    zip_file = build_qr_download_zip(items)
    return send_file(zip_file, mimetype='application/zip', as_attachment=True, download_name='all_qr_codes.zip')


@app.route('/download/selected', methods=['POST'])
def download_selected():
    selected_ids = [item for item in request.form.getlist('selected_ids') if item.isdigit()]
    if not selected_ids:
        return redirect(url_for('history'))

    items = fetch_qr_items(selected_ids)
    zip_file = build_qr_download_zip(items)
    return send_file(zip_file, mimetype='application/zip', as_attachment=True, download_name='selected_qr_codes.zip')


if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
else:
    init_db()
