from google.cloud import bigquery
from datetime_utils import time_to_str
import logging

l = logging.getLogger("bigquery-ethereum-crawler.ethereum_bigquery")


class EthereumBigQuery(object):
    def __init__(self):
        self.client = bigquery.Client()

    def get_ethereum_data(self, from_time, to_time):
        query_str = (
            f'SELECT * FROM `bigquery-public-data.ethereum_blockchain.traces` '
            f'WHERE block_timestamp >= "{time_to_str(from_time)}" AND block_timestamp < "{time_to_str(to_time)}" AND from_address IS NOT NULL'
        )

        return self.client.query(query_str).result()
