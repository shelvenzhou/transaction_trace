from ..local import EthereumDatabase
import sys
import os


class TraceAnalysis:
    def __init__(self, db_folder=None, log_file=sys.stdout, db_list=None):
        if db_folder != None:
            if db_list == None:
                self.database = EthereumDatabase(db_folder)
            else:
                self.database = dict()
                db_folders = os.listdir(db_folder)
                for db_name in db_list:
                    if f'ethereum_{db_name}' in db_folders:
                        self.database[db_name] = EthereumDatabase(
                            os.path.join(db_folder, f'ethereum_{db_name}'), db_name)

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
