import os
import sys
import asyncio
import pickle
import sqlite3
from transaction_trace.local import Etherscan


async def main(db_filepath, api_key_filepath, addrs_filepath):
    es = Etherscan(api_key_filepath, db_filepath, '')
    es.create_contracts_table()
    with open(addrs_filepath, 'rb') as f:
        addrs = pickle.load(f)

    con = sqlite3.connect('/home/xiangjie/database/etherscan.sqlite3')
    cur = con.cursor()
    rows = cur.execute('select ContractAddress, SourceCode from contracts')
    addrs_in_database = set()
    for row in rows:
        addrs_in_database.add(row[0])


    count = len(addrs)
    for addr in addrs:
        count -= 1
        if addr in addrs_in_database:
            continue
        if len(addr) != 42 or not addr.startswith('0x'):
            print('not valid address')
        else:
            await es.get_contract_info(addr)
            print(count, 'left')

    await es.client.close()


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 %s db_filepath api_key_filepath addrs_filepath" %
              sys.argv[0])
        exit(-1)

    asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3]))
