import logging
from datetime import datetime, timedelta

from datetime_utils import date_to_str, str_to_time, time_to_str
from local.ethereum_database import EthereumDatabase
from remote.ethereum_bigquery import EthereumBigQuery

l = logging.getLogger("transaction-trace.utilities.crawler")
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def main():
    remote = EthereumBigQuery()

    # data insertion
    try:
        with open("logs/crawl-time", "r") as f:
            from_time = str_to_time(f.readline())
    except:
        from_time = datetime(2017, 9, 29, 23, 0, 0)

    to_time = from_time + timedelta(hours=1)

    while True:
        date = from_time.date()
        local = EthereumDatabase(
            f"/Users/Still/Desktop/w/db/bigquery_ethereum-t_{date_to_str(date)}.sqlite3")
        try:
            local.database_create()
        except:
            print("datebase already exists")

        print(f"date:", date_to_str(date))
        while from_time.date() == date:

            print(f"query from {from_time} to {to_time}...")
            rows = remote.get_ethereum_data(from_time, to_time)

            trace_count = local.database_insert(rows)
            print(f"{trace_count} inserted")
            local.update_crawl_records(from_time, to_time, trace_count)
            local.database_commit()

            to_time = from_time
            from_time = from_time - timedelta(hours=1)
            with open("logs/crawl-time", "w+") as f:
                f.write(time_to_str(from_time))


if __name__ == "__main__":
    main()
