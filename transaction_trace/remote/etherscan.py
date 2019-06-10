import json

from aioetherscan import Client


class Etherscan:

    def __init__(self, api_key_filepath):
        with open(api_key_filepath, 'r') as key_file:
            key = json.loads(key_file.read())['key']

        self.client = Client(key)

    def __del__(self):
        self.client.close()

    async def get_contract_info(self, addr):
        try:
            contract = (await self.client.contract.contract_source_code(addr))[0]
        except Exception as e:
            print(e)
            return
        contract['ContractAddress'] = addr

        return contract
