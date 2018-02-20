from setuptools import setup, find_packages
from os import path

current_dir = path.abspath(path.dirname(__file__))

with open(path.join(current_dir, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='detect',
    version='1.2.0',
    description='Console fun and easy to use tool for network and os detection',
    long_description=long_description,
    author='Ofir Korzi and Roni Dromi',
    classifiers=[
        'Development Status :: 3 - Alpha',

        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    packages=find_packages(),
    install_requires=['pyprinter', 'scapy-python3', 'netifaces', 'logbook'],
    entry_points={
        'console_scripts': [
            'scan-network=detect.run:scan_network',
            'scan-wan-network=detect.run:scan_wan_network',
            'scan=detect.run:scan',
            'scan-host=detect.run:scan_host',
            'scan-help=detect.run:print_help'
        ],
    },
)
