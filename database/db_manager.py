import sqlite3

DB = "data/threat_db.sqlite"

def create_table():

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS iocs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT,
        value TEXT UNIQUE,
        source TEXT,
        timestamp TEXT,
        category TEXT,
        severity TEXT
    )
    """)

    conn.commit()
    conn.close()

def insert_ioc(ioc):

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute(
        """
        INSERT OR IGNORE INTO iocs
        (type,value,source,timestamp,category,severity)
        VALUES(?,?,?,?,?,?)
        """,
        (
            ioc["type"],
            ioc["value"],
            ioc["source"],
            ioc["timestamp"],
            ioc["category"],
            "LOW"
        )
    )

    conn.commit()
    conn.close()

def get_all_iocs():

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("SELECT * FROM iocs ORDER BY id DESC")

    rows = c.fetchall()

    conn.close()

    return rows