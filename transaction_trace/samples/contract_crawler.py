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

    bytecode_hash2contracts = addrs['bytecode_hash2contracts']
    func_hash = list(bytecode_hash2contracts.keys())

    addrs_in_database = set()
    l.create_contracts_table()
    rows = l.read('contracts', '*')
    for row in rows:
        addrs_in_database.add(row[0])


    count = len(func_hash)
    for h in func_hash:
        for addr in bytecode_hash2contracts[h]:
            if addr in addrs_in_database:
                continue
            if len(addr) != 42 or not addr.startswith('0x'):
                print('not valid address')
            else:
                contract = await r.get_contract_info(addr)
                if contract == None:
                    continue
                row = [contract[x] for x in ContractCode.key_order]
                try:
                    l.insert_contract(row)
                    l.commit()
                except:
                    pass
                if row[1] != '':
                    for c in bytecode_hash2contracts[h]:
                        try:
                            row[0] = c
                            l.insert_contract(row)
                        except:
                            pass
                    l.commit()
                    break
        count -= 1
        print(count, ' bytecode hash left')

    await r.client.close()


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 %s db_filepath api_key_filepath addrs_filepath" %
              sys.argv[0])
        exit(-1)

    asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3]))
