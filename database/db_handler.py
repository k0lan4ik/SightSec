import sqlite3

class Database:
    def __init__(self, db_name="scanner_data.db"):
        self.conn = sqlite3.connect(db_name)
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                name TEXT,
                severity TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )
        ''')
        self.conn.commit()

    def save_scan(self, target, vulns):
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO scans (target) VALUES (?)", (target,))
        scan_id = cursor.lastrowid
        
        for v in vulns:
            cursor.execute(
                "INSERT INTO vulnerabilities (scan_id, name, severity) VALUES (?, ?, ?)",
                (scan_id, v.name, v.severity)
            )
        self.conn.commit()