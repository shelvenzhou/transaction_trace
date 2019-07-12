import sys

from web3 import Web3

from ..intermediate_representations import ResultType


class CheckerType:

    TRANSACTION_CENTRIC = 'TRANSACTION_CENTRIC'
    CONTRACT_CENTRIC = 'CONTRACT_CENTRIC'


class Checker:

    def __init__(self, checker_name):
        self.checker_name = checker_name

    @property
    def name(self):
        return self.checker_name

    @property
    def minimum_profit_amount(self):
        return {
            ResultType.ETHER_TRANSFER: Web3.toWei(0.00001, 'ether'),
            ResultType.TOKEN_TRANSFER: 100
        }

    @property
    def checker_type(self):
        raise NotImplementedError

    def check_transaction(self, action_tree, result_graph):
        """
        A transaction-centric checker must implement this.

        It checks the abnormal actions and sensitive results caused by them, and return the addresses of victim
        and attack contract for further filter.
        """
        raise NotImplementedError

    def check_contract(self, contract, related_txs):
        """
        A contract-centric checker must implement this.

        It checks the ordered list of transactions which operate on the contract, and return the addresses of victim
        and attack contract for further filter.
        """
        raise NotImplementedError
