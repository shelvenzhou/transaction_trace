import sqlite3
import decimal
from datetime_utils import *
from local.ethereum_database import EthereumDatabase


def transfer_text(s):
    if s == "None":
        return None
    return s


def text2int(s):
    if s == "None":
        return None

    return int(s)


def text2decimal(s):
    if s == "None":
        return None

    return decimal.Decimal(s)


transfer_funcs = list((
    transfer_text,  # transaction_hash TEXT,
    text2int,  # transaction_index INT,
    transfer_text,  # from_address TEXT,
    transfer_text,  # to_address TEXT,
    text2decimal,  # value DECIMAL,
    transfer_text,  # input TEXT,
    transfer_text,  # output TEXT,
    transfer_text,  # trace_type TEXT NOT NULL,
    transfer_text,  # call_type TEXT,
    transfer_text,  # reward_type TEXT,
    text2int,  # gas INT,
    text2int,  # gas_used INT,
    text2int,  # subtraces INT,
    transfer_text,  # trace_address TEXT,
    transfer_text,  # error TEXT,
    text2int,  # status INT,
    str_to_time,  # block_timestamp TIMESTAMP NOT NULL,
    text2int,  # block_number INT NOT NULL,
    transfer_text,  # block_hash STRING NOT NULL
))


def list_factory(cursor, row):
    l = list()
    for idx, _ in enumerate(cursor.description):
        l.append(transfer_funcs[idx](row[idx]))
    return l


def main(db_filepath):
    conn = sqlite3.connect(db_filepath, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = list_factory
    cur = conn.cursor()

    local = EthereumDatabase()
    local.database_create()

    print("database created")

    insert_count = 0
    cur.execute("SELECT * FROM traces;")
    while True:
        rows = cur.fetchmany(100000)
        if len(rows) == 0:
            break

        local.database_insert(rows)
        local.database_commit()

        insert_count += len(rows)
        print("%d rows inserted" % insert_count)


if __name__ == "__main__":
    main("big_query_test.db")
