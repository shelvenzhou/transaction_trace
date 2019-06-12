from setuptools import find_packages, setup

packages = find_packages()

setup(
    name='transaction_trace',
    version='0.1',
    python_requires='>=3.7',
    description='Smart contract traffic analysis tool',
    packages=packages,
    install_requires=[
        'sortedcontainers',
        'networkx',
        'web3',
        'numpy',
        'scipy',
        'py-etherscan-api',
        'eth_abi',
        'google-cloud-storage',
    ],
)
