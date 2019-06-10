import asyncio
import pickle
import sys

from transaction_trace.local import ContractCode
from transaction_trace.remote import Etherscan


async def main(db_filepath, api_key_filepath, addrs_filepath):
    r = Etherscan(api_key_filepath)
    l = ContractCode(db_filepath, '')

    with open(addrs_filepath, 'rb') as f:
        addrs = pickle.load(f)

    l.create_contracts_table()
    rows = l.read('contracts', 'ContractAddress, SourceCode')
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
            contract = await r.get_contract_info(addr)
            l.insert_contract([contract[x] for x in ContractCode.key_order])
            print(count, 'left')

    await r.client.close()


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 %s db_filepath api_key_filepath addrs_filepath" %
              sys.argv[0])
        exit(-1)

    asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3]))
