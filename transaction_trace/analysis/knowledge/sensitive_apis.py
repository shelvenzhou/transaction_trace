import binascii
import logging
from eth_abi.exceptions import InsufficientDataBytes
from eth_abi import decode_abi

from ..intermediate_representations import ResultType

l = logging.getLogger("transaction-trace.analysis.knowledge.SensitiveAPIs")


def _extract_function_signature(input_data):
    if input_data is None:
        return None

    return input_data[:10]


def _extract_function_parameters(func_name, input_data):
    if input_data is None:
        return None

    paras = func_name.split('(')[1].split(')')[0].split(',')

    return decode_abi(paras, bytes.fromhex(input_data[10:]))


class SensitiveAPIs:

    _sensitive_functions = {
        'owner': {
            '0x13af4035': 'setOwner(address)',
            '0xe46dcfeb': 'initWallet(address[],uint256,uint256)',
            '0xf2fde38b': 'transferOwnership(address)',
            '0xa6f9dae1': 'changeOwner(address)',
            '0x7065cb48': 'addOwner(address)',
        },
        'token': {
            '0xa9059cbb': 'transfer(address,uint256)',
            '0x23b872dd': 'transferFrom(address,address,uint256)',
            '0x40c10f19': 'mint(address,uint256)',
            '0xb5e73249': 'mint(address,uint256,bool,uint32)',
            '0xf0dda65c': 'mintTokens(address,uint256)',
            '0x79c65068': 'mintToken(address,uint256)',
            '0x449a52f8': 'mintTo(address,uint256)',
            '0x2f81bc71': 'multiMint(address[],uint256[])',
        }
    }

    _encoded_functions = None

    _sensitive_para_index = {
        '0x13af4035': 0,
        '0xe46dcfeb': 0,
        '0xf2fde38b': 0,
        '0xa6f9dae1': 0,
        '0x7065cb48': 0,
        '0xa9059cbb': (0, 1),
        '0x23b872dd': (0, 1, 2),
        '0x40c10f19': (0, 1),
        '0xb5e73249': (0, 1),
        '0xf0dda65c': (0, 1),
        '0x79c65068': (0, 1),
        '0x449a52f8': (0, 1),
        '0x2f81bc71': (0, 1),
    }

    @classmethod
    def encoded_functions(cls):
        if cls._encoded_functions is None:
            cls._encoded_functions = {
                'owner': {},
                'token': {},
            }
            for t in _sensitive_functions:
                for sig, func in _sensitive_functions[t]:
                    cls._encoded_functions[t][sig] = binascii.b2a_hex(func.encode("utf-8")).decode()

        return cls._encoded_functions

    @classmethod
    def owner_change_functions(cls):
        return cls.encoded_functions['owner']

    @classmethod
    def token_transfer_functions(cls):
        return cls.encoded_functions['token']

    @classmethod
    def sensitive_function_call(cls, input_data):
        callee = _extract_function_signature(input_data)
        return callee in cls._sensitive_functions['owner'] or callee in cls._sensitive_functions['token']

    @classmethod
    def get_result_details(cls, trace):
        input_data = trace['input']

        result_type = None
        src = trace['from_address']

        sig = _extract_function_signature(input_data)
        if sig in cls._sensitive_functions['owner']:
            func_name = cls._sensitive_functions['owner'][sig]

            try:
                paras = _extract_function_parameters(func_name, input_data)
            except InsufficientDataBytes as e:
                l.exception("transaction %s", trace['transaction_hash'])
                return

            _dst = paras[cls._sensitive_para_index[sig]]

            if isinstance(_dst, str):
                yield ResultType.OWNER_CHANGE, src, _dst, None
            else:
                for dst in _dst:
                    yield ResultType.OWNER_CHANGE, src, dst, None

        elif sig in cls._sensitive_functions['token']:
            func_name = cls._sensitive_functions['token'][sig]

            try:
                paras = _extract_function_parameters(func_name, input_data)
            except InsufficientDataBytes as e:
                l.exception("transaction %s", trace['transaction_hash'])
                return

            index = cls._sensitive_para_index[sig]
            if len(index) == 2:  # (to, amount)
                _dst = paras[index[0]]
                _amount = paras[index[1]]

                if isinstance(_dst, str):
                    yield ResultType.TOKEN_TRANSFER, src, _dst, _amount
                else:
                    for dst, amount in zip(_dst, _amount):
                        yield ResultType.TOKEN_TRANSFER, src, dst, amount
            else:  # (from, to, amount)
                src = paras[index[0]]
                dst = paras[index[1]]
                amount = paras[index[2]]
                yield ResultType.TOKEN_TRANSFER, src, dst, amount

        else:  # this should never be reached
            l.warning("unknown sensitive function signature %s", sig)
            import IPython
            IPython.embed()
