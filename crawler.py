from datetime import datetime,timedelta
import logging
from remote.ethereum_bigquery import EthereumBigQuery
from local.ethereum_database import EthereumDatabase
from datetime_utils import str_to_time,time_to_str

l = logging.getLogger("bigquery-ethereum-crawler")
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def main():
    remote = EthereumBigQuery()
    local = EthereumDatabase("/Users/Still/Desktop/w/db/bigquery_ethereum-t.sqlite3")

    # database table init
    # local.database_create()

    # data insertion
    try:
        with open("crawl-time", "r") as f:
            from_time = str_to_time(f.readline())
    except:
        from_time = datetime(2018, 9, 24, 18, 0, 0)
    to_time = from_time + timedelta(hours=1)

    while True:
        print(f"query from {from_time} to {to_time}...")
        rows = remote.get_ethereum_data(from_time, to_time)
        
        trace_count = local.database_insert(rows)
        print(f"{trace_count} inserted")
        local.update_crawl_records(from_time, to_time, trace_count)
        local.database_commit()

        to_time = from_time
        from_time = from_time - timedelta(hours=1)
        with open("crawl-time", "w+") as f:
            f.write(time_to_str(from_time))

if __name__ == "__main__":
    main()
