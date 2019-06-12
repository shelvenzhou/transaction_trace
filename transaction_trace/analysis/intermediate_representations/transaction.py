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

    def __repr__(self):
        return "meta-data of transaction %s" % self.tx_hash
