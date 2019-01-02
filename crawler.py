from datetime import datetime

from remote.ethereum_bigquery import EthereumBigQuery
from local.ethereum_database import EthereumDatabase


def main():
    remote = EthereumBigQuery()
    local = EthereumDatabase()

    # database table init
    # local.database_create()

    # data insertion
    from_time = datetime(2018, 12, 27, 1, 1, 1) # 2018-12-27 1:1:1
    to_time = datetime(2018, 12, 27, 1, 2, 1) # 2018-12-27 1:2:1

    rows = remote.get_ethereum_data(from_time, to_time)
    local.database_insert(rows)
    local.update_crawl_records(from_time, to_time, -1)
    local.database_commit()

if __name__ == "__main__":
    main()
