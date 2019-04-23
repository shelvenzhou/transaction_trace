from ..local import EthereumDatabase

class TraceAnalysis:
    def __init__(self, db_folder, log_file):
        self.database = EthereumDatabase(db_folder)
        self.log_file = log_file

    def record_abnormal_detail(self, detail):
        print(detail, file=self.log_file)
