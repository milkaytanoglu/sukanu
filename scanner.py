from database import init_db
import os
from sqlite3 import dbapi2 as sqlite3
from time import sleep
import re

init_db()

nuclei_path = '~/go/bin/nuclei'
katana_path = '~/go/bin/katana'
subfinder_path = '~/go/bin/subfinder'

"""
subfinder -d example.com -o subfinder.txt
katana -u example.com -o katana.txt
nuclei -target example.com -o nuclei.txt
"""

def subfinder(domain):
    os.system(f'{subfinder_path} -d {domain} -o subfinder.txt')
    results = []
    if not os.path.exists('subfinder.txt'):
        return results
    with open('subfinder.txt', 'r') as f:
        for line in f:
            results.append(line)
    # delete subfinder.txt content
    with open('subfinder.txt', 'w') as f:
        f.write('')   
    return results
    
    
def katana(domain):
    os.system(f'{katana_path} -u {domain} -o katana.txt')
    results = []
    if not os.path.exists('katana.txt'):
        return results
    with open('katana.txt', 'r') as f:
        for line in f:
            results.append(line)
    # delete katana.txt content
    with open('katana.txt', 'w') as f:
        f.write('')
    return results


def nuclei(domain):
    os.system(f'{nuclei_path} -target {domain} -o nuclei.txt')
    results = []
    if not os.path.exists('nuclei.txt'):
        return results
    with open('nuclei.txt', 'r') as f:
        for line in f:
            results.append(line)
    # delete nuclei.txt content
    with open('nuclei.txt', 'w') as f:
        f.write('')
    return results

"""
[tls-version] [ssl] [info] www.techard.net:443 ["tls12"]
[tls-version] [ssl] [info] www.techard.net:443 ["tls13"]
[dns-saas-service-detection:wix] [dns] [info] www.techard.net ["cdn1.wixdns.net"]
[caa-fingerprint] [dns] [info] www.techard.net
[caa-fingerprint] [dns] [info] https://www.techard.net:443 ["CAA record found"]
[ssl-issuer] [ssl] [info] www.techard.net:443 ["Google Trust Services"]
[ssl-dns-names] [ssl] [info] www.techard.net:443 ["techard.net","www.techard.net"]
[mx-service-detector:Google Apps] [dns] [info] fatihzor.dev
"""
def nuclei_crawl_info(line):
    match = re.match(r"\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*)", line)
    if match:
        category, protocol, level, message = match.groups()
        
        # Mesajdaki ek bilgileri kontrol et
        extra_info_match = re.search(r"\[(.*?)\]$", message)
        extra_info = extra_info_match.group(1) if extra_info_match else None
        main_message = re.sub(r"\[.*?\]$", "", message).strip()
        
        return {
            "category": category,
            "protocol": protocol,
            "level": level,
            "message": main_message,
            "extra_info": extra_info
        }
    return None

if __name__ == '__main__':
    while True:
        db = sqlite3.connect('db.sqlite3')
        cursor = db.cursor()
        cursor.execute('''
            SELECT id, domain FROM targets WHERE status = 'pending'
        ''')
        targets = cursor.fetchall()
        db.close()
        if not targets:
            print('No pending targets')
            sleep(5)
            continue
        for target in targets:
            target_id, domain = target
            db = sqlite3.connect('db.sqlite3')
            cursor = db.cursor()
            cursor.execute('''
                UPDATE targets SET status = ? WHERE id = ?
            ''', ('scanning', target_id))
            db.commit()
            db.close()
            
            subfinder_results = subfinder(domain)
            katana_results = katana(domain)
            nuclei_results = nuclei(domain)
            
            db = sqlite3.connect('db.sqlite3')
            cursor = db.cursor()
            for result in subfinder_results:
                cursor.execute('''
                    INSERT INTO subfinder_results (target_id, domain, status) VALUES (?, ?, ?)
                ''', (target_id, result, 'new'))
            for result in katana_results:
                cursor.execute('''
                    INSERT INTO katana_results (target_id, domain, status) VALUES (?, ?, ?)
                ''', (target_id, result, 'new'))
            for result in nuclei_results:
                info = nuclei_crawl_info(result)
                if not info:
                    continue
                cursor.execute('''
                    INSERT INTO nuclei_results (target_id, category, protocol, level, message, extra_info, status) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (target_id, info['category'], info['protocol'], info['level'], info['message'], info['extra_info'], 'new'))    
                
            cursor.execute('''
                UPDATE targets SET status = ? WHERE id = ?
            ''', ('scanned', target_id))
            db.commit()
            db.close()
            print(f'Scanned {domain}')
            