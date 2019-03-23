import sqlite3
from datetime_utils import date_to_str
from local.ethereum_database import EthereumDatabase
import sys
from datetime import datetime, timedelta


def main(db_path):
    from_time = datetime(2018, 10, 7, 0, 0, 0)
    to_time = datetime(2018, 10, 7, 0, 0, 0)
    date = from_time.date()
    print("start transfer...")
    while date <= to_time.date():
        print(date_to_str(date))
        db = EthereumDatabase(
            f"{db_path}/bigquery_ethereum_{date_to_str(date)}.sqlite3")
        try:
            db.read_from_database(
                table="subtraces", columns="trace_id", clause="limit 1")
            del db
            print("no need to transfer")
        except:
            rows = db.read_from_database(
                table="subtraces", columns="*").fetchall()
            print(len(rows), "subtraces")
            db.drop_index("subtraces_transaction_hash_index")
            db.cur.execute("drop table subtraces")
            db.cur.execute("""
                CREATE TABLE subtraces(
                    transaction_hash TEXT,
                    trace_id INT PRIMARY KEY,
                    parent_trace_id INT
                );
            """)
            for row in rows:
                db.write_into_database(table="subtraces", columns="transaction_hash, trace_id, parent_trace_id", placeholder="?, ?, ?", vals=row)
            db.database_commit()
            del db, rows
            
        date += timedelta(days=1)


if __name__ == "__main__":
    main(sys.argv[1])
