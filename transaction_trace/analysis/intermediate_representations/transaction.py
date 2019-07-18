from ...basic_utils import DatetimeUtils


class Transaction:

    def __init__(self, tx_hash, block_number, tx_index, block_timestamp, block_hash, caller):
        self.tx_hash = tx_hash

        self.block_number = block_number
        self.tx_index = tx_index

        self.block_timestamp = block_timestamp
        self.block_hash = block_hash

        self.caller = caller

        self.is_attack = False
        self.attack_details = list()

        self.destruct_contracts = list()

    def __repr__(self):
        return "meta-data of transaction %s" % self.tx_hash

    def to_string(self):
        tx_detail = {
            'tx_hash': self.tx_hash,
            'block_timestamp': DatetimeUtils.time_to_str(self.block_timestamp),
            'caller': self.caller,
            'attack_details': self.attack_details
        }
        return str(tx_detail)

    @staticmethod
    def from_dict(d):
        tx = Transaction(d['tx_hash'], None, None, DatetimeUtils.str_to_time(d['block_timestamp']), None, d['caller'])
        if len(d['attack_details']) > 0:
            tx.is_attack = True
            tx.attack_details = d['attack_details']
        return tx
