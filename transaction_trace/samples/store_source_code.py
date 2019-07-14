import json
import logging
import pickle
import sys

import transaction_trace
from transaction_trace.local import ContractCode, EthereumDatabase
from transaction_trace.local.database_name import DatabaseName

l = logging.getLogger("store_source_code")


def main(bytecode_db_folder, source_code_filepath, bytecode_hash_index, mysql_password, cache_len=100000):
    l.info("open bytecode databases in %s", bytecode_db_folder)
    bytecode_db = EthereumDatabase(bytecode_db_folder, db_name=DatabaseName.CONTRACT_DATABASE)

    l.info("load source code from %s", source_code_filepath)
    with open(source_code_filepath, "r") as f:
        source_codes = json.load(f)

    l.info("load bytecode hash index from %s", bytecode_hash_index)
    with open(bytecode_hash_index, "rb") as f:
        dct = pickle.load(f)
        hash_contracts = dct["bytecode_hash2contracts"]
        contract_hash = dct["contract2bytecode_hash"]

    dst_db = ContractCode(passwd=mysql_password)
    dst_db.create_tables()
    db_cache = list()

    bytecode_cols = [
        'address', 'bytecode', 'bytecode_hash', 'function_sighashes',
        'is_erc20', 'is_erc721', 'block_timestamp', 'block_number', 'block_hash'
    ]
    for conn in bytecode_db.get_all_connnections():
        l.info("insert bytecode from %s", conn)
        for bytecode_row in conn.read_contracts():
            row = dict(bytecode_row)
            row["bytecode_hash"] = contract_hash[row["address"]]

            db_cache.append([row[k] for k in bytecode_cols])
            if len(db_cache) > cache_len:
                for r in db_cache:
                    dst_db.insert_byte_code(r)
                dst_db.commit()
                db_cache.clear()
    for r in db_cache:
        dst_db.insert_byte_code(r)
    dst_db.commit()
    db_cache.clear()

    sourcecode_cols = [
        "CodeHash", "SourceCode", "ABI", "ContractName", "CompilerVersion",
        "OptimizationUsed", "Runs", "ConstructorArguments", "Library", "SwarmSource"
    ]
    l.info("insert source code")
    for s in source_codes:
        if s["SourceCode"] == "":
            continue

        db_cache.append([s[k] for k in sourcecode_cols])
        if len(db_cache) > cache_len:
            for r in db_cache:
                dst_db.insert_source_code(r)
            dst_db.commit()
            db_cache.clear()
    for r in db_cache:
        dst_db.insert_source_code(r)
    dst_db.commit()
    db_cache.clear()


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 %s bytecode_db_folder source_code_filepath bytecode_hash_index mysql_password" %
              sys.argv[0])
        exit(-1)

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
