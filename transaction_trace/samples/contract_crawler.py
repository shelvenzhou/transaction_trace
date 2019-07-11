import asyncio
import pickle
import sys
from threading import Thread, Event
from queue import Queue

from transaction_trace.local import ContractCode
from transaction_trace.remote import Etherscan


def migrate_data(db_filepath, addrs_filepath):
    l = ContractCode(db_filepath, '')

    with open(addrs_filepath, 'rb') as f:
        addrs = pickle.load(f)

    bytecode_hash2contracts = addrs['bytecode_hash2contracts']
    contract2bytecode_hash = addrs['contract2bytecode_hash']

    addrs_in_database = list()
    hash2source_code = dict()

    print("processing old data")
    rows = l.read('contracts', '*')
    for row in rows:
        addr = row['ContractAddress']
        if addr not in contract2bytecode_hash:
            print(list(row))
            continue
        h = contract2bytecode_hash[addr]
        r = list(row)
        r[0] = h
        addrs_in_database.append(addr)

        if h not in hash2source_code:
            hash2source_code[h] = r
        elif hash2source_code[h][1] == '' and r[1] != '':
            hash2source_code[h] = r

    l.create_contracts_table()
    print("inserting contract")
    for addr in addrs_in_database:
        try:
            l.insert_contract_bytecode_hash([addr, contract2bytecode_hash[addr]])
        except:
            pass
    l.commit()
    print("inserting bytecode hash")
    for h in hash2source_code:
        r = hash2source_code[h]
        try:
            l.insert_source_code(r)
        except:
            pass
    l.commit()

def process_db(queue, db_filepath):
    l = ContractCode(db_filepath, '')
    code_in_database = dict()
    for row in l.read('source_code', '*'):
        h = row['BytecodeHash']
        code = row['SourceCode']
        code_in_database[h] = code if code == '' else '0x'

    while True:
        item = queue.get()
        queue.task_done()
        t = item[0]
        row = item[1]
        if t == 'code':
            if row[0] in code_in_database and (code_in_database[row[0]] != '' or row[1] == ''):
                continue
            try:
                l.insert_source_code(row)
            except Exception as e:
                print(e)
                l.update_source_code(row[0], row)
        else:
            try:
                l.insert_contract_bytecode_hash(row)
            except:
                pass
        l.commit()

async def main(db_filepath, api_key_filepath, addrs_filepath):
    queue = Queue()
    db_processor = Thread(target=process_db, args=(queue, db_filepath,))
    db_processor.start()

    r = Etherscan(api_key_filepath)
    l = ContractCode(db_filepath, '')

    contract_in_database = set()
    for row in l.read('contract_bytecode_hash', '*'):
        contract_in_database.add(row['ContractAddress'])

    code_in_database = dict()
    for row in l.read('source_code', '*'):
        h = row['BytecodeHash']
        code = row['SourceCode']
        code_in_database[h] = code if code == '' else '0x'

    with open(addrs_filepath, 'rb') as f:
        addrs = pickle.load(f)
    bytecode_hash2contracts = addrs['bytecode_hash2contracts']

    count = len(bytecode_hash2contracts)
    for h in bytecode_hash2contracts:
        for addr in bytecode_hash2contracts[h]:
            if addr in contract_in_database and h in code_in_database and code_in_database[h] != '':
                continue
            if len(addr) != 42 or not addr.startswith('0x'):
                print('not valid address')
            else:
                if addr not in contract_in_database:
                    queue.put(('addr', [addr, h]))
                if h not in code_in_database or code_in_database[h] == '':
                    contract = await r.get_contract_info(addr)
                    if contract == None:
                        continue
                    row = [contract[x] for x in ContractCode.key_order]
                    row[0] = h
                    queue.put(('code', row))

                    if row[1] != '':
                        for c in bytecode_hash2contracts[h]:
                            if c not in contract_in_database:
                                queue.put(('addr', [c, h]))
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
    # migrate_data(sys.argv[1], sys.argv[3])
