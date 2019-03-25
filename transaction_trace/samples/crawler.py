import logging
from datetime import datetime, timedelta
import sqlite3

import transaction_trace
from transaction_trace.datetime_utils import date_to_str, str_to_time, time_to_str
from transaction_trace.local.database import Database
from transaction_trace.remote.ethereum_bigquery import EthereumBigQuery

l = logging.getLogger("transaction-trace.utilities.crawler")
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def main():
    remote = EthereumBigQuery()

    # data insertion
    try:
        with open("/home/xiangjie/logs/crawl-time", "r") as f:
            from_time = str_to_time(f.readline())
    except:
        from_time = datetime(2015, 8, 7, 0, 0, 0)

    to_time = from_time + timedelta(hours=1)

    while from_time < datetime(2019, 3, 20, 0, 0, 0):
        date = from_time.date()
        local = Database(
            f"/mnt/data/bigquery/ethereum_blocks/blocks_{date_to_str(date)}.sqlite3")
        try:
            local.create_table(table_name="blocks", columns='''(
                timestamp TIMESTAMP NOT NULL,
                number INT NOT NULL,
                hash TEXT NOT NULL,
                parent_hash TEXT,
                nonce TEXT NOT NULL,
                sha3_uncles TEXT,
                logs_bloom TEXT,
                transactions_root TEXT,
                state_root TEXT,
                receipts_root TEXT,
                miner TEXT,
                difficulty INT,
                total_difficulty INT,
                size INT,
                extra_data TEXT,
                gas_limit INT,
                gas_used INT,
                transaction_count INT
                )''')
        except sqlite3.Error as e:
            print(e)

        print(f"date:", date_to_str(date))
        while from_time.date() == date:

            print(f"query from {from_time} to {to_time}...")
            rows = remote.get_ethereum_data(from_time, to_time)
            count = 0
            for row in rows:
                block_count = local.insert(table="blocks", 
                    columns="(timestamp, number, hash, parent_hash, nonce, sha3_uncles, logs_bloom, transactions_root, state_root, receipts_root, miner, difficulty, total_difficulty, size, extra_data, gas_limit, gas_used, transaction_count)", 
                    placeholders="?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?", rows=row)
                count += 1
            print(count, "blocks")
            # local.update_crawl_records(from_time, to_time, trace_count)
            local.commit()

            from_time = to_time
            to_time += timedelta(hours=1)
            with open("/home/xiangjie/logs/crawl-time", "w+") as f:
                f.write(time_to_str(from_time))


if __name__ == "__main__":
    main()
