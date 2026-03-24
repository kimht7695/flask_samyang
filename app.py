import base64
import io
import os
import secrets
import sqlite3
from datetime import datetime
from urllib.parse import urlencode

import qrcode
from flask import Flask, g, jsonify, redirect, render_template, request, url_for, send_file

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


def ensure_column(db, table_name: str, column_name: str, column_def: str):
    cols = [row[1] for row in db.execute(f"PRAGMA table_info({table_name})").fetchall()]
    if column_name not in cols:
        db.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_def}")


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
            browser_name TEXT,
            os_name TEXT,
            device_type TEXT,
            referer TEXT,
            accept_language TEXT,
            latitude REAL,
            longitude REAL,
            location_note TEXT,
            FOREIGN KEY(qr_id) REFERENCES qr_tokens(id)
        )
        '''
    )
    ensure_column(db, 'scan_logs', 'browser_name', 'TEXT')
    ensure_column(db, 'scan_logs', 'os_name', 'TEXT')
    ensure_column(db, 'scan_logs', 'device_type', 'TEXT')
    ensure_column(db, 'scan_logs', 'referer', 'TEXT')
    ensure_column(db, 'scan_logs', 'accept_language', 'TEXT')
    ensure_column(db, 'scan_logs', 'latitude', 'REAL')
    ensure_column(db, 'scan_logs', 'longitude', 'REAL')
    ensure_column(db, 'scan_logs', 'location_note', 'TEXT')
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


def detect_client_info(user_agent: str):
    ua = (user_agent or '').lower()
    browser = 'Unknown'
    os_name = 'Unknown'
    device = 'PC'

    if 'edg/' in ua:
        browser = 'Edge'
    elif 'chrome/' in ua and 'edg/' not in ua:
        browser = 'Chrome'
    elif 'safari/' in ua and 'chrome/' not in ua:
        browser = 'Safari'
    elif 'firefox/' in ua:
        browser = 'Firefox'
    elif 'trident/' in ua or 'msie' in ua:
        browser = 'Internet Explorer'

    if 'android' in ua:
        os_name = 'Android'
        device = 'Mobile'
    elif 'iphone' in ua or 'ipad' in ua:
        os_name = 'iOS'
        device = 'Mobile'
    elif 'windows' in ua:
        os_name = 'Windows'
    elif 'mac os x' in ua or 'macintosh' in ua:
        os_name = 'macOS'
    elif 'linux' in ua:
        os_name = 'Linux'

    if 'tablet' in ua or 'ipad' in ua:
        device = 'Tablet'
    elif 'mobile' in ua or 'android' in ua or 'iphone' in ua:
        device = 'Mobile'

    return browser, os_name, device


def clean_ip(raw_ip: str):
    if not raw_ip:
        return ''
    return raw_ip.split(',')[0].strip()


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
            qr_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]

            qr_url = f"{get_base_url()}{url_for('scan', token=token)}?{urlencode({'r': random_param})}"
            created = {
                'id': qr_id,
                'name': name,
                'target_url': target_url,
                'token': token,
                'random_param': random_param,
                'qr_url': qr_url,
                'qr_image': make_qr_data_uri(qr_url),
            }

    qr_list = db.execute('SELECT * FROM qr_tokens ORDER BY id DESC LIMIT 20').fetchall()
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
    ip_address = clean_ip(request.headers.get('X-Forwarded-For', request.remote_addr or ''))
    user_agent = request.headers.get('User-Agent', '')
    browser_name, os_name, device_type = detect_client_info(user_agent)
    referer = request.headers.get('Referer', '')
    accept_language = request.headers.get('Accept-Language', '')

    db.execute(
        '''
        INSERT INTO scan_logs (
            qr_id, scanned_at, ip_address, user_agent, browser_name, os_name,
            device_type, referer, accept_language
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (qr['id'], now, ip_address, user_agent, browser_name, os_name, device_type, referer, accept_language)
    )
    log_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
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

    template = 'authentic.html' if updated_qr['scan_count'] == 1 else 'counterfeit.html'
    return render_template(template, qr=updated_qr, logs=logs, latest_log_id=log_id)


@app.post('/api/scan-log/<int:log_id>/location')
def save_location(log_id):
    db = get_db()
    row = db.execute('SELECT id FROM scan_logs WHERE id = ?', (log_id,)).fetchone()
    if row is None:
        return jsonify({'ok': False, 'message': 'scan log not found'}), 404

    data = request.get_json(silent=True) or {}
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    location_note = (data.get('location_note') or '').strip()[:255]

    db.execute(
        'UPDATE scan_logs SET latitude = ?, longitude = ?, location_note = ? WHERE id = ?',
        (latitude, longitude, location_note, log_id)
    )
    db.commit()
    return jsonify({'ok': True})


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


@app.route('/stats')
def stats_index():
    db = get_db()
    items = db.execute(
        '''
        SELECT q.id, q.name, q.target_url, q.scan_count, q.created_at,
               MAX(s.scanned_at) AS last_scanned_at
        FROM qr_tokens q
        LEFT JOIN scan_logs s ON q.id = s.qr_id
        GROUP BY q.id
        ORDER BY q.id DESC
        '''
    ).fetchall()
    summary = db.execute(
        '''
        SELECT COUNT(*) AS total_qr,
               COALESCE(SUM(scan_count), 0) AS total_scans
        FROM qr_tokens
        '''
    ).fetchone()
    return render_template('stats_index.html', items=items, summary=summary)


@app.route('/stats/<int:qr_id>')
def stats_detail(qr_id):
    db = get_db()
    qr = db.execute('SELECT * FROM qr_tokens WHERE id = ?', (qr_id,)).fetchone()
    if qr is None:
        return render_template('invalid.html'), 404

    logs = db.execute(
        '''
        SELECT * FROM scan_logs
        WHERE qr_id = ?
        ORDER BY id DESC
        ''',
        (qr_id,)
    ).fetchall()

    by_ip = db.execute(
        '''
        SELECT COALESCE(ip_address, '-') AS label, COUNT(*) AS cnt
        FROM scan_logs
        WHERE qr_id = ?
        GROUP BY COALESCE(ip_address, '-')
        ORDER BY cnt DESC, label ASC
        LIMIT 10
        ''',
        (qr_id,)
    ).fetchall()

    by_browser = db.execute(
        '''
        SELECT TRIM(COALESCE(browser_name, 'Unknown') || ' / ' || COALESCE(os_name, 'Unknown')) AS label,
               COUNT(*) AS cnt
        FROM scan_logs
        WHERE qr_id = ?
        GROUP BY label
        ORDER BY cnt DESC, label ASC
        LIMIT 10
        ''',
        (qr_id,)
    ).fetchall()

    recent_locations = db.execute(
        '''
        SELECT scanned_at, ip_address, latitude, longitude, location_note
        FROM scan_logs
        WHERE qr_id = ?
          AND (latitude IS NOT NULL OR longitude IS NOT NULL OR COALESCE(location_note, '') != '')
        ORDER BY id DESC
        LIMIT 20
        ''',
        (qr_id,)
    ).fetchall()

    return render_template(
        'stats_detail.html',
        qr=qr,
        logs=logs,
        by_ip=by_ip,
        by_browser=by_browser,
        recent_locations=recent_locations,
    )


@app.route('/qr/<int:qr_id>/download')
def download_qr(qr_id):
    db = get_db()
    qr = db.execute('SELECT * FROM qr_tokens WHERE id = ?', (qr_id,)).fetchone()
    if qr is None:
        return render_template('invalid.html'), 404

    qr_url = f"{get_base_url()}{url_for('scan', token=qr['token'])}?{urlencode({'r': qr['random_param']})}"
    png = make_qr_png_bytes(qr_url)
    filename = f"qr_{qr['id']}_{qr['name']}.png".replace(' ', '_')
    return send_file(io.BytesIO(png), mimetype='image/png', as_attachment=True, download_name=filename)


if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
else:
    init_db()
