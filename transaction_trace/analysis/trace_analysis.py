from ..local import EthereumDatabase


class TraceAnalysis:
    def __init__(self, db_folder, log_file):
        self.database = EthereumDatabase(db_folder)
        self.log_file = log_file

    def record_abnormal_detail(self, *args):
        if len(args) == 1:
            print(args[0], file=self.log_file)
        else:
            date = args[0]
            abnormal_type = args[1]
            detail = args[2]
            print("[%s][%s]: %s" %
                  (date, abnormal_type, detail), file=self.log_file)
