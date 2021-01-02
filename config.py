"""
Open Nodes configuration
Copyright (c) 2018 Opennodes / Blake Bjorn Anderson

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import logging
import os
import re
import requests
import yaml
import binascii
import dotenv
from ipaddress import ip_network

dotenv.load_dotenv()
DATABASE_URI = os.environ.get("DATABASE_URI", "sqlite:///nodes.sqlite")

def list_excluded_networks(networks):
    """
    Converts list of networks from configuration file into a list of tuples of
    network address and netmask to be excluded from the crawl.
    """
    networks_out = set()
    for addr in networks:
        addr = str(addr).split('#')[0].strip()
        try:
            network = ip_network(addr)
        except ValueError:
            continue
        else:
            networks_out.add((int(network.network_address), int(network.netmask)))
    return networks_out


def get_ipv4_bogons():
    url = "http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt"
    try:
        response = requests.get(url, timeout=15)
    except requests.exceptions.RequestException as err:
        logging.warning(err)
    else:
        if response.status_code == 200:
            return response.content.decode("utf8").splitlines()
    return []


def load_config():
    with open("crawler_config.yml", "r") as f:
        conf = yaml.load(f, yaml.SafeLoader)

    if os.path.isfile("crawler_user_config.yml"):
        with open("crawler_user_config.yml", "r") as f:
            conf2 = yaml.load(f, yaml.SafeLoader)
        conf.update(conf2)

    if 'networks' in conf:
        for network in conf['networks']:
            conf['networks'][network]['magic_number'] = binascii.unhexlify(
                conf['networks'][network]['magic_number'])

    if 'exclude_ipv4_bogons' in conf and conf['exclude_ipv4_bogons']:
        conf['exclude_ipv4_networks'] = list(set(conf['exclude_ipv4_networks'] + get_ipv4_bogons()))

    if 'exclude_ipv4_networks' in conf:
        conf['exclude_ipv4_networks'] = list_excluded_networks(conf['exclude_ipv4_networks'])

    if 'excluded_user_agents' in conf:
        conf['excluded_user_agents'] = [re.compile(x, re.IGNORECASE) for x in conf['excluded_user_agents']]

    if 'user_agent' in conf:
        conf['user_agent'] = conf['user_agent'].encode()

    if 'tor_proxy' in conf and conf['tor_proxy']:
        assert ":" in conf['tor_proxy']
        port = int(conf['tor_proxy'].split(":")[-1])
        address = conf['tor_proxy'].split(f":{port}")[0]
        conf['tor_proxy'] = (address, port)

    return conf
