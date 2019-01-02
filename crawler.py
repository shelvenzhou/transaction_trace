from datetime import datetime,timedelta
import logging
from remote.ethereum_bigquery import EthereumBigQuery
from local.ethereum_database import EthereumDatabase

l = logging.getLogger("bigquery-ethereum-crawler")
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def main():
    remote = EthereumBigQuery()
    local = EthereumDatabase()

    # database table init
    # local.database_create()

    # data insertion
    from_time = datetime(2018, 10, 3, 22, 0, 0)
    to_time = datetime(2018, 10, 3, 23, 0, 0)

    while True:
        print(f"query from {from_time} to {to_time}...")
        rows = remote.get_ethereum_data(from_time, to_time)
        
        trace_count = local.database_insert(rows)
        print(f"{trace_count} inserted")
        local.update_crawl_records(from_time, to_time, trace_count)
        local.database_commit()

        to_time = from_time
        from_time = from_time - timedelta(hours=1)

if __name__ == "__main__":
    main()
