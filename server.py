from flask import Flask, request, jsonify, render_template, redirect, url_for
import re
from sqlite3 import dbapi2 as sqlite3

from database import init_db

app = Flask(__name__)

@app.route('/'  , methods=['GET'])
def index():
    db = sqlite3.connect('db.sqlite3')
    cursor = db.cursor()
    cursor.execute('''
        SELECT * FROM targets
    ''')
    targets = cursor.fetchall()
    db.close()
    return render_template('index.html', targets=targets)

@app.route('/scan'  , methods=['POST'])
def scan():
    domain = request.form['domain']
    get_domain = domain.split('//')[-1]
    domain = get_domain.split('/')[0]
    
    domain_regex = '[a-zA-Z0-9.-]*$'
    
    if not re.match(domain_regex, domain):
        return jsonify({'error': 'Invalid domain'})
    db = sqlite3.connect('db.sqlite3')
    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO targets (domain, status) VALUES (?, ?)
    ''', (domain, 'pending'))
    db.commit()
    db.close()
    
    
    return redirect(url_for('index'))

@app.route('/results/<int:target_id>'  , methods=['GET'])
def results(target_id):
    db = sqlite3.connect('db.sqlite3')
    cursor = db.cursor()
    cursor.execute('''
        SELECT * FROM targets WHERE id = ?
    ''', (target_id,))
    target = cursor.fetchone()
    cursor.execute('''
        SELECT * FROM subfinder_results WHERE target_id = ?
    ''', (target_id,))
    subfinder_results = cursor.fetchall()
    cursor.execute('''
        SELECT * FROM katana_results WHERE target_id = ?
    ''', (target_id,))
    katana_results = cursor.fetchall()
    cursor.execute('''
        SELECT * FROM nuclei_results WHERE target_id = ?
    ''', (target_id,))
    nuclei_results = cursor.fetchall()
    db.close()
    return render_template('results.html', target=target, subfinder_results=subfinder_results, katana_results=katana_results, nuclei_results=nuclei_results)

@app.route('/delete/<int:target_id>'  , methods=['GET'])
def delete(target_id):
    db = sqlite3.connect('db.sqlite3')
    cursor = db.cursor()
    cursor.execute('''
        DELETE FROM targets WHERE id = ?
    ''', (target_id,))
    cursor.execute('''
        DELETE FROM subfinder_results WHERE target_id = ?
    ''', (target_id,))
    cursor.execute('''
        DELETE FROM katana_results WHERE target_id = ?
    ''', (target_id,))
    cursor.execute('''
        DELETE FROM nuclei_results WHERE target_id = ?
    ''', (target_id,))
    db.commit()
    db.close()
    return redirect(url_for('index'))

@app.route('/reset/<int:target_id>'  , methods=['GET'])
def reset(target_id):
    db = sqlite3.connect('db.sqlite3')
    cursor = db.cursor()
    cursor.execute('''
        UPDATE targets SET status = ? WHERE id = ?
    ''', ('pending', target_id))
    cursor.execute('''
        DELETE FROM subfinder_results WHERE target_id = ?
    ''', (target_id,))
    cursor.execute('''
        DELETE FROM katana_results WHERE target_id = ?
    ''', (target_id,))
    cursor.execute('''
        DELETE FROM nuclei_results WHERE target_id = ?
    ''', (target_id,))
    db.commit()
    db.close()
    return redirect(url_for('index'))

@app.route('/add-to-scan'  , methods=['GET'])
def add_to_scan():
    domain = request.args.get('domain')    
    get_domain = domain.split('//')[-1]
    domain = get_domain.split('/')[0]
    
    domain_regex = '[a-zA-Z0-9.-]*$'
    
    if not re.match(domain_regex, domain):
        return jsonify({'error': 'Invalid domain'})
    db = sqlite3.connect('db.sqlite3')
    cursor = db.cursor()
    
    cursor.execute('''
        INSERT INTO targets (domain, status) VALUES (?, ?)
    ''', (domain, 'pending'))
    db.commit()
    db.close()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)