import logging
from datetime import datetime

from google.cloud import bigquery

from ..datetime_utils import time_to_str
from .remote_data_source import RemoteDateSource

l = logging.getLogger("transaction-trace.remote.ethereum_bigquery")


class EthereumBigQuery(RemoteDateSource):
    def __init__(self):
        self.client = bigquery.Client()

    def get_ethereum_data(self, from_time, to_time):
        query_str = (
            f'SELECT * FROM `bigquery-public-data.ethereum_blockchain.blocks` '
            f'WHERE timestamp >= "{time_to_str(from_time)}" AND timestamp < "{time_to_str(to_time)}"'
        )

        return self.client.query(query_str).result()
