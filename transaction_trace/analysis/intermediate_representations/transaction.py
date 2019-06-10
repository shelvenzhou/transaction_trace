class Transaction:
    def __init__(self, tx_hash, block_number, tx_index, block_timestamp, block_hash, caller):
        self.tx_hash = tx_hash

        self.block_number = block_number
        self.tx_index = tx_index

        self.block_timestamp = block_timestamp
        self.block_hash = block_hash

        self.caller = caller
