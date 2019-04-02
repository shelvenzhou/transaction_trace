import logging
from collections import defaultdict
from sortedcontainers import SortedList
from datetime import timedelta, timezone

from ..datetime_utils import str_to_date, time_to_str
from ..local import EthereumDatabase

l = logging.getLogger("transaction-trace.analysis.TrafficAnalyzer")

class TrafficAnalyzer:
    def __init__(self, db_folder, log_file):
        self.database = EthereumDatabase(db_folder)
        self.log_file = log_file

    def record_abnormal_detail(self, date, abnormal_type, detail):
        print("[%s][%s]: %s" %
              (date, abnormal_type, detail), file=self.log_file)

    def find_block_jam(self, from_time, to_time, t):
        blocks = defaultdict(dict)
        for db_conn in self.database.get_connections(from_time, to_time):
            for row in db_conn.read(table="blocks", columns="*"):
                number = row["number"]
                blocks[number] = {
                    "timestamp": row["timestamp"],
                    "gas_limit": row["gas_limit"],
                    "gas_used": row["gas_used"],
                    "transaction_count": row["transaction_count"]
                }
        if len(blocks) == 0:
            print("no blocks")
            exit(-1)
        average_tx_count = 0
        for b_num in blocks:
            average_tx_count += blocks[b_num]["transaction_count"]
        average_tx_count /= len(blocks)

        jammed_blocks = SortedList()
        for b_num in blocks:
            if blocks[b_num]["gas_used"]/blocks[b_num]["gas_limit"] > 0.9 and blocks[b_num]["transaction_count"] < average_tx_count/int(t):
                jammed_blocks.add(b_num)

        import IPython;IPython.embed()