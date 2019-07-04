from .checker import Checker
from ...local import DatabaseName
from ..knowledge import SensitiveAPIs
from ...datetime_utils import time_to_str


from collections import defaultdict
import logging

l = logging.getLogger("transaction-trace.analysis.checkers.CADChecker")

class CallAfterDestructChecker(Checker):

    def __init__(self, log_file):
        super(CallAfterDestructChecker, self).__init__("call-after-destruct-checker")
        self.database = None
        self.log_file = log_file


    def do_check(self, txs, db):
        if self.database == None:
            self.database = db
        destruct_contracts = defaultdict(dict)
        for tx in txs:
            if len(tx.destruct_contracts) == 0:
                continue
            for contract in destruct_contracts:
                destruct_contracts[contract['contract']] = {
                    'destruct_time': time_to_str(tx['block_timestamp']),
                    'destruct_tx_hash': tx.tx_hash,
                    'value': contract['value']
                }
        self.check_destruct_contracts(destruct_contracts)

    def check_destruct_contracts(self, destruct_contracts):
        for conn in self.database[DatabaseName.TRACE_DATABASE].get_all_connnections():
            traces = defaultdict(list)
            for row in conn.read('traces', "transaction_hash, from_address, to_address, value, input, status, block_timestamp"):
                if row['trace_type'] != 'call':
                    continue
                tx_hash = row['transaction_hash']
                traces[tx_hash].append(row)

            for tx_hash in traces:
                call_after_destruct = list()
                for trace in traces[tx_hash]:
                    if trace["status"] == 0:
                        continue
                    to_address = trace["to_address"]
                    if to_address in destruct_contracts and time_to_str(trace["block_timestamp"]) > destruct_contracts[to_address]["destruct_time"]:
                        if SensitiveAPIs.sensitive_function_call(trace["input"]):
                            callee = SensitiveAPIs.func_name(trace["input"])
                            detail = {
                                "destruct_contract": to_address,
                                "destruct_time": destruct_contracts[to_address]["destruct_time"],
                                "destruct_tx_hash": destruct_contracts[to_address]["destruct_tx_hash"],
                                "callee": callee,
                                "value": trace["value"]
                            }
                            call_after_destruct.append(detail)
                        elif trace["value"] > 0:
                            detail = {
                                "destruct_contract": to_address,
                                "destruct_time": destruct_contracts[to_address]["destruct_time"],
                                "destruct_tx_hash": destruct_contracts[to_address]["destruct_tx_hash"],
                                "value": trace["value"]
                            }
                            call_after_destruct.append(detail)

                if len(call_after_destruct) > 0:
                    l.info("CallAfterDestruct found for tx: %s", tx_hash)
                    tx_detail = {
                        'tx_hash': tx_hash,
                        'block_timestamp': time_to_str(traces[tx_hash][0]["block_timestamp"]),
                        'cad_details': call_after_destruct
                    }
                    print(tx_detail, file=self.log_file)
