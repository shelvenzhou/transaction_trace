import logging
from datetime import datetime, timedelta
import sqlite3
import sys
import os

from transaction_trace.datetime_utils import date_to_str, str_to_time, time_to_str, str_to_date
from transaction_trace.local.single_database import *
from transaction_trace.local.ethereum_database import db_filename
from transaction_trace.remote.ethereum_bigquery import EthereumBigQuery

l = logging.getLogger("transaction-trace.utilities.crawler")
logger = logging.getLogger()
logger.setLevel(logging.INFO)


database_map = {
    "traces": {
        "class_name": "SingleTraceDatabase",
        "create": "create_traces_table",
        "insert": "insert_traces"
    },
    "blocks": {
        "class_name": "SingleBlockDatabase",
        "create": "create_blocks_table",
        "insert": "insert_blocks"
    },
    "transactions": {
        "class_name": "SingleTransactionDatabase",
        "create": "create_txs_table",
        "insert": "insert_txs"
    }
}


def main(db_folder, crawl_time_path, time_interval, to_time, from_time):
    remote = EthereumBigQuery()
    db_name = db_folder.split("_")[-1]
    # data insertion
    try:
        with open(crawl_time_path, "r") as f:
            from_time = str_to_time(f.readline())
    except:
        if from_time == None:
            print("from_time not set")
            exit(-1)
        from_time = str_to_date(from_time)
    t_time = from_time + timedelta(hours=int(time_interval))

    while from_time < str_to_date(to_time):
        date = from_time.date()
        date_str = date_to_str(date)
        db_filepath = os.path.join(db_folder, db_filename(db_name, date_str))
        # import IPython;IPython.embed()
        db = globals()[database_map[db_name]["class_name"]](db_filepath, date_str)
        try:
            getattr(db, database_map[db_name]["create"])()
        except sqlite3.Error as e:
            print(e)

        print(f"date:", date_str)
        while from_time.date() == date:

            print(f"query from {from_time} to {t_time}...")
            rows = remote.get_ethereum_data(from_time, t_time, db_name)
            count = 0
            for row in rows:
                getattr(db, database_map[db_name]["insert"])(row)
                count += 1
            print(count, "txs")
            db.commit()

            from_time = t_time
            t_time += timedelta(hours=1)
            with open(crawl_time_path, "w+") as f:
                f.write(time_to_str(from_time))


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python3 %s db_folder crawl_time_path time_interval to_time [from_time]" %
              sys.argv[0])
        exit(-1)

    if len(sys.argv) == 5:
        sys.argv[5] = None

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
