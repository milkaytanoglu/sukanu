from sqlite3 import dbapi2 as sqlite3
import os
"""
targets
    id
    domain
    status
    created_at
    updated_at

subfinder_results
    id
    target_id
    domain
    status
    created_at
    updated_at
    
katana_results
    id
    target_id
    domain
    status
    created_at
    updated_at

nuclei_results
    id
    target_id
    domain
    status
    created_at
    updated_at
"""
db_path = 'db.sqlite3'


def init_db():
    
    if not db_path:
        return
    if not db_path.endswith('.sqlite3'):
        return
    if os.path.exists(db_path):
        return
    
    db = sqlite3.connect('db.sqlite3')
    cursor = db.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS subfinder_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            domain TEXT,
            status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS katana_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            domain TEXT,
            status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nuclei_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            category TEXT,
            protocol TEXT,
            level TEXT,
            message TEXT,
            extra_info TEXT,
            status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    db.commit()
    db.close()

