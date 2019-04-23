import logging
from collections import defaultdict
from datetime import timedelta, timezone

from sortedcontainers import SortedList

from ..datetime_utils import date_to_str, str_to_date, time_to_str
from .trace_analysis import TraceAnalysis

l = logging.getLogger("transaction-trace.analysis.TrafficAnalyzer")


class TrafficAnalyzer(TraceAnalysis):
    def __init__(self, db_folder, log_file):
        super(TrafficAnalyzer, self).__init__(db_folder, log_file)

    def find_block_jam(self, from_time, to_time, t):
        blocks = defaultdict(dict)
        l.info("prepare block data from %s to %s",
               from_time, to_time)
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
            l.error("no blocks")
            exit(-1)
        average_tx_count = defaultdict(lambda: defaultdict(int))
        l.info("compute average transaction count monthly")
        for b_num in blocks:
            date = date_to_str(blocks[b_num]["timestamp"])
            average_tx_count[date]["tx_count"] += blocks[b_num]["transaction_count"]
            average_tx_count[date]["block_count"] += 1
        for date in average_tx_count:
            tx_count = average_tx_count[date]["tx_count"]
            block_count = average_tx_count[date]["block_count"]
            average_tx_count[date] = tx_count/block_count

        jammed_blocks = SortedList()
        l.info("finding jammed blocks")
        for b_num in blocks:
            date = date_to_str(blocks[b_num]["timestamp"])
            block_time = time_to_str(blocks[b_num]["timestamp"])
            average = average_tx_count[date]
            tx_count = blocks[b_num]["transaction_count"]
            if blocks[b_num]["gas_used"]/blocks[b_num]["gas_limit"] > 0.95 and average > 20 and tx_count < float(t):
                jammed_blocks.add(b_num)
<<<<<<< HEAD
                l.info(
                    f"jammed block found on {block_time}, average: {average}, tx_count: {tx_count}, number: {b_num}")
                self.record_abnormal_detail(
                    block_time, "BLOCKJAM", f"average: {average}, tx_count: {tx_count}, block_number: {b_num}")
=======
                l.info(f"jammed block found on {block_time}, average: {average}, tx_count: {tx_count}, number: {b_num}")
                detail = {
                    "date": block_time,
                    "abnormal_type": "BLOCKJAM",
                    "average": average,
                    "tx_count": tx_count,
                    "block_number": b_num
                }
                self.record_abnormal_detail(detail)
>>>>>>> perf: log print

        import IPython
        IPython.embed()
