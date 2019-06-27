from .checker import Checker, CheckerType
from ..intermediate_representations import ResultType
from ...local.ethereum_database import EthereumDatabase
from ..knowledge.sensitive_apis import SensitiveAPIs
from ...datetime_utils import date_to_str


from collections import defaultdict


class ProfitChecker(Checker):

    def __init__(self, db_folder):
        super(ProfitChecker, self).__init__("profit-checker")
        self.trace_db = EthereumDatabase(db_folder)

    @property
    def checker_type(self):
        return CheckerType.CONTRACT_CENTRIC

    def extract_profit_candidates(self, attack_details):
        # extract candidate attack profits for call-injection & reentrancy from raw result
        candidates = defaultdict(dict)
        for checker_result in attack_details:
            if checker_result['checker'] not in ('call-injection', 'reentrancy'):
                continue

            candidate_profits = defaultdict(dict)
            # for node in checker_result['profit']:
            #     for result_type in checker_result['profit'][node]:
            #         candidate_profits[node][result_type] = {
            #             'victims': set(),
            #             'amount': checker_result['profit'][node][result_type]
            #         }

            for item in checker_result['profit']:
                candidate_profits[item['node']][item['result_type']] = {
                    'victims': set(),
                    'amount': item['amount'] if 'amount' in item else None
                }

            for attack in checker_result['attacks']:
                for item in attack['result']:
                    profit_node = item['edge'][0]
                    victim_node = item['edge'][1]

                    if profit_node in checker_result['profit'] and item['result_type'] in checker_result['profit'][profit_node]:
                        candidate_profits[profit_node][item['result_type']]['victims'].add(
                            victim_node)

            # for attack in checker_result['attacks']:
            #     for e in attack['results']:
            #         profit_node = e[1]
            #         victim_node = e[0]

            #         for result_type in attack['results'][e]:
            #             if profit_node in checker_result['profit'] and result_type in checker_result['profit'][profit_node]:
            #                 candidate_profits[profit_node][result_type]['victims'].add(
            #                     victim_node)

            # only keep the profit nodes with victims
            profits = defaultdict(dict)
            for node in candidate_profits:
                for result_type in candidate_profits[node]:
                    if len(candidate_profits[node][result_type]['victims']) > 0:
                        profits[node][result_type] = candidate_profits[node][result_type]

            candidates[checker_result['checker']] = profits

        return candidates

    def check_contract_income_forward(self, db, contract, account, income_type, timestamp):
        income = 0
        txs = db.read_transactions_of_contract(contract)
        for date in txs:
            if date > date_to_str(timestamp):
                continue
            con = self.trace_db.get_connection(date)
            traces = defaultdict(list)
            for row in conn.read_traces():
                if row['trace_type'] not in ('call', 'create', 'suicide'):
                    continue
                tx_hash = row['transaction_hash']
                traces[tx_hash].append(row)

            for tx_hash in traces:
                if date == date_to_str(timestamp) and traces[tx_hash][0]['block_timestamp'] >= timestamp:
                    continue
                for trace in traces[tx_hash]:
                    if trace['status'] == 0:
                        continue

                    if income_type == ResultType.ETHER_TRANSFER and account in (trace['from_address'], trace['to_address']) and trace['value'] > 0:
                        if trace['from_address'] == contract:
                            amount -= trace['value']
                        elif trace['to_address'] == contract:
                            amount += contract
                    elif SensitiveAPIs.sensitive_function_call(trace['input']):
                        # check input data for token transfer and owner change
                        for result_type, src, dst, amount in SensitiveAPIs.get_result_details(trace):
                            if result_type == ResultType.TOKEN_TRANSFER:
                                if src == contract and dst == account:
                                    income -= amount
                                elif dst == contract and src == account:
                                    income += amount

        return income

    def check_contract(self, tx, db):
        # extract the candidate attack profits
        candidates = self.extract_profit_candidates(tx.attack_details)

        for checker in candidates:
            for profit_node in candidates[checker]:
                for result_type in candidates[checker][profit_node]:
                    if result_type == ResultType.OWNER_CHANGE:
                        candidates[checker][profit_node][result_type] = 1
                    outlay = 0
                    for victim in candidates[checker][profit_node][result_type]['victims']:
                        outlay += self.check_contract_income_forward(
                            db, victim, profit_node, result_type, tx.block_timestamp)

                    net_profit = candidates[checker][profit_node][result_type]['amount'] - outlay
                    candidates[checker][profit_node][result_type] = net_profit

        attack_net_profit = dict()
        for checker in candidates:
            net_profits = defaultdict(dict)
            for profit_node in candidates[checker]:
                for result_type in candidates[checker][profit_node]:
                    if candidates[checker][profit_node][result_type] > 0:
                        net_profits[profit_node][result_type] = candidates[checker][profit_node][result_type]
            if len(net_profits) > 0:
                attack_net_profit[checker] = net_profits
            else:
                attack_net_profit[checker] = None

        attack_details = list()
        for checker_result in tx.attack_details:
            if checker_result['checker'] in attack_net_profit:
                if attack_net_profit[checker_result['checker']] != None:
                    checker_result['net_profit'] = attack_net_profit[checker_result['checker']]
                    attack_details.append(checker_result)
            else:
                attack_details.append(checker_result)
        tx.attack_details = attack_details
        if len(attack_details) == 0:
            tx.is_attack == False
