import logging
from collections import defaultdict

from ...basic_utils import DatetimeUtils
from ...local import DatabaseName
from ..knowledge import SensitiveAPIs
from ..results import AttackCandidate
from .checker import Checker, CheckerType

l = logging.getLogger("transaction-trace.analysis.checkers.CallAfterDestructChecker")


class CallAfterDestructChecker(Checker):

    def __init__(self, attack_candidate_exporter):
        super(CallAfterDestructChecker, self).__init__("call-after-destruct-checker")
        self.out = attack_candidate_exporter

    @property
    def checker_type(self):
        return CheckerType.CONTRACT_CENTRIC

    def do_check(self, **kwargs):
        self.check_destruct_contracts()

    def check_destruct_contracts(self):
        destruct_contracts = dict()
        for conn in self.database[DatabaseName.TRACE_DATABASE].get_all_connnections():
            traces = dict()
            for row in conn.read('traces', "transaction_hash, from_address, to_address, value, input, status, block_timestamp"):
                if row['trace_type'] not in ('call', 'suicide'):
                    continue
                block_timestamp = DatetimeUtils.time_to_str(row['block_timestamp'])
                if block_timestamp not in traces:
                    traces[block_timestamp] = defaultdict(list)

                tx_hash = row['transaction_hash']
                traces[block_timestamp][tx_hash].append(row)

            for block_timestamp in sorted(list(traces.keys())):
                for tx_hash in traces[block_timestamp]:
                    candidate = AttackCandidate(
                        self.name,
                        {
                            'transaction': tx_hash,
                            'block_timestamp': block_timestamp,
                            'calls': []
                        },
                        {'eth_loss': 0},
                    )
                    for trace in traces[block_timestamp][tx_hash]:
                        if trace["status"] == 0:
                            continue

                        to_address = trace["to_address"]
                        if trace['trace_type'] == 'suicide':
                            destruct_contracts[to_address] = {
                                'destruct_time': block_timestamp,
                                'destruct_tx_hash': tx_hash,
                                'value': trace['value']
                            }
                            continue

                        if to_address in destruct_contracts and block_timestamp > destruct_contracts[to_address]["destruct_time"]:
                            if SensitiveAPIs.sensitive_function_call(trace["input"]):
                                called_func = SensitiveAPIs.func_name(trace["input"])
                                candidate.details['calls'].append({
                                    'sensitive_func': called_func,
                                    'target': {
                                        'contract_address': to_address,
                                        'destruct_time': destruct_contracts[to_address]["destruct_time"]
                                    }
                                })
                            candidate.results['eth_loss'] += trace['value']

                    if candidate.details['calls'] or candidate.results['eth_loss']:
                        l.info("CallAfterDestruct found for tx: %s", tx_hash)
                        out.dump_candidate(candidate)
