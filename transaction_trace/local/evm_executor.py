import os
import re
import subprocess
import sys

access_re = re.compile("storage ([^:]*):\[([^:]*): ([^\]]*)\]")


class EVMExecutor:

    def __init__(self, cache_len=100000):
        self.evm = "evm_{}".format(sys.platform)

        current_dir = os.path.dirname(os.path.realpath(__file__))
        self.evm_filepath = os.path.join(current_dir + "/../res/bin", self.evm)

        self._storage_access_cache = dict()
        self._access_history = list()
        self._cache_len = cache_len

    def deployed_code(self, creation_code):
        result = subprocess.run([self.evm_filepath,
                                 "--create",
                                 "--code", creation_code.replace("0x", ""),
                                 "run"], stdout=subprocess.PIPE)
        return result.stdout.decode("utf-8").split("\n")[-2]

    def log_storage_accesses(self, deployed_code, input_data):
        if deployed_code is None:
            return set()

        code = deployed_code.replace("0x", "")
        i = input_data.replace("0x", "")

        if (code, i) in self._access_history:
            self._access_history.remove((code, i))
            self._access_history.append((code, i))
            return self._storage_access_cache[(code, i)]
        if len(self._access_history) == self._cache_len:
            lru = self._access_history.pop(0)
            self._storage_access_cache.pop(lru)

        result = subprocess.run([self.evm_filepath,
                                 "--code", code,
                                 "--input", i,
                                 "run"], stdout=subprocess.PIPE)
        output = result.stdout.decode("utf-8")

        access_log = list()
        for op, loc, val in access_re.findall(output):
            access_log.append((op, int(loc, 16)))

        self._access_history.append((code, i))
        self._storage_access_cache[(code, i)] = access_log

        return access_log
