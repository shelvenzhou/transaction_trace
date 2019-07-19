import os

from ..local import EthereumDatabase


class TraceAnalysis:
    def __init__(self, db_folder=None, db_list=None):
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
