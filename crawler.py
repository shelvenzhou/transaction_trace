from datetime import datetime

from ethereum_bigquery import EthereumBigQuery
from ethereum_database import EthereumDatabase


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
    local.database_commit()

if __name__ == "__main__":
    main()
