from collections import defaultdict

import numpy as np
from scipy.cluster.hierarchy import fcluster, linkage
from sortedcontainers import SortedDict


def txs_distance(a, b):
    inter = 0
    union = 0
    for i in range(len(a)):
        if a[i] or b[i]:
            union += 1
        if a[i] and b[i]:
            inter += 1
    return (union-inter)/union


class TransactionCluster:
    def __init__(self, name):
        self._name = name

    def __repr__(self):
        return self._name

    def hierarchy_cluster(self, tx2sigs, t, criterion="inconsistent", method="average", metric=txs_distance):
        sig_dict = SortedDict()
        for tx_hash in tx2sigs:
            for sig in tx2sigs[tx_hash]:
                sig_dict[sig] = 0

        txs2vector = list()
        for tx_hash in tx2sigs:
            sig_vector = sig_dict.copy()
            for sig in tx2sigs[tx_hash]:
                sig_vector[sig] = 1
            txs2vector.append((tx_hash, np.array(sig_vector.values())))

        vectors = list()
        for one in txs2vector:
            vectors.append(one[1])
        z = linkage(vectors, method, metric)
        cluster = fcluster(z, t, criterion)

        txs_cluster = defaultdict(list)
        for i in range(0, len(cluster)):
            txs_cluster[cluster[i]].append(txs2vector[i][0])
        txs_cluster = SortedDict(txs_cluster)

        return txs_cluster
