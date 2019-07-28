import os
import re
import subprocess
import sys

load_re = re.compile("storage load:\[([^:]*): ([^\]]*)\]")
store_re = re.compile("storage store:\[([^:]*): ([^\]]*)\]")


class StorageAccessLog:

    def __init__(self):
        self.loads = set()
        self.stores = set()


class EVMExecutor:

    def __init__(self):
        self.evm = "evm_{}".format(sys.platform)

        current_dir = os.path.dirname(os.path.realpath(__file__))
        self.evm_filepath = os.path.join(current_dir + "/../res/bin", self.evm)

    def log_storage_accesses(self, contract_code, input_data):
        result = subprocess.run([self.evm_filepath,
                                 "--create",
                                 "--code", contract_code,
                                 "run"], stdout=subprocess.PIPE)
        real_code = result.stdout.decode("utf-8").split("\n")[-2]

        result = subprocess.run([self.evm_filepath,
                                 "--code", real_code,
                                 "--input", input_data,
                                 "run"], stdout=subprocess.PIPE)
        output = result.stdout.decode("utf-8")

        access_log = StorageAccessLog()
        for loc, val in load_re.findall(output):
            access_log.loads.add(loc)
        for loc, val in store_re.findall(output):
            access_log.stores.add(loc)
        return access_log
