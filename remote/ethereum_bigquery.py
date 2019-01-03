from google.cloud import bigquery
from .remote_datasource import RemoteDateSource
import logging
from datetime import datetime

DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def time_to_str(t):
    return t.strftime(DATETIME_FORMAT)


def str_to_time(s):
    return datetime.strptime(s, DATETIME_FORMAT)


l = logging.getLogger("bigquery-ethereum-crawler.remote.ethereum_bigquery")


class EthereumBigQuery(RemoteDateSource):
    def __init__(self):
        self.client = bigquery.Client()

    def get_ethereum_data(self, from_time, to_time):
        query_str = (
            f'SELECT * FROM `bigquery-public-data.ethereum_blockchain.traces` '
            f'WHERE block_timestamp >= "{time_to_str(from_time)}" AND block_timestamp < "{time_to_str(to_time)}" AND from_address IS NOT NULL'
        )

        return self.client.query(query_str).result()
