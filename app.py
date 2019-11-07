"""
Open Nodes web server
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

import gzip
import json
import os
import sys
from io import BytesIO

from flask import Flask, render_template, request, redirect, flash, Response
from flask_sqlalchemy import SQLAlchemy
from geoip2.errors import AddressNotFoundError
from sqlalchemy import and_

from config import load_config, DefaultFlaskConfig
from crawler import COUNTRY, CITY, ASN, connect, update_masternode_list
from models import *
import pandas as pd
from autodoc import Autodoc


app = Flask(__name__)
auto = Autodoc(app)
app.config.from_object(DefaultFlaskConfig())
app.config.from_object('flask_config')
db = SQLAlchemy(app)

CONF = load_config()

@app.route('/')
@app.route('/networks/<network_name>', methods=['GET'])
def network_dashboard(network_name=None):
    if not network_name in ("bitcoin", "bitcoin-cash", "litecoin", "dash", "bitcoin-sv", None):
        flash("Invalid network")
        return redirect("/")

    with open("static/network_summaries.json", 'r') as f:
        summaries = json.load(f)

    if network_name:
        age_min = summaries[network_name]['age_min']
        age_max = summaries[network_name]['age_max']
    else:
        age_min = min((summaries[network]['age_min'] for network in CONF['networks']))
        age_max = max((summaries[network]['age_max'] for network in CONF['networks']))

    return render_template("network_dashboard.html",
                           network=network_name,
                           has_masternodes=True if network_name == "dash" else False,
                           include_client=False if network_name is not None else False,
                           include_user_agent=True if network_name is not None else False,
                           include_network=True if network_name is None else False,
                           include_version=True if network_name is not None else False,
                           include_active=True if CONF['export_inactive_nodes'] else False,
                           age_min=age_min * 1000.0,
                           age_max=age_max * 1000.0)


def gzip_response(input_str, pre_compressed):
    response = Response()
    if not pre_compressed:
        buffer = BytesIO()
        gzip_file = gzip.GzipFile(mode='wb', fileobj=buffer)
        gzip_file.write(input_str if isinstance(input_str, bytes) else input_str.encode())
        gzip_file.close()
        response.data = buffer.getvalue()
    else:
        response.data = input_str
    response.headers['Content-Encoding'] = 'gzip'
    response.headers['Vary'] = 'Accept-Encoding'
    response.headers['Content-Length'] = len(response.data)
    return response


@app.route('/api/get_networks', methods=['POST'])
@auto.doc()
def get_networks():
    """
    Returns a list of all available network names
    :return: JSON string, ex. "['bitcoin','bitcoin-cash','dash','litecoin']"
    """
    return json.dumps([x[0] for x in db.session.query(Node.network).distinct().all()])


@app.route('/api/gzip_file/<filename>', methods=['GET'])
@auto.doc()
def gzip_static_file(filename):
    """
    Returns a crawl result as a gzipped response
    :param filename: file_network.ext - file is 'data' or 'history',  ext is either .json, .csv, .txt (data.ext returns data for all crawled networks)
    :return: gzip encoded html response
    """
    valid_files = ["custom.geo.json"]
    for coin in ("", "_bitcoin", "_bitcoin-cash", "_dash", "_litecoin", "_bitcoin-sv"):
        for suff in ("", "_unique"):
            for ext in (".csv", ".json", ".txt"):
                valid_files.append("data" + coin + suff + ext)
        valid_files.append("history" + coin + '.json')
    if filename not in valid_files:
        return redirect("/", code=404)
    with open(os.path.join("static", filename), "r") as f:
        return gzip_response(f.read(), False)

def deconstruct_address_string(inp):
    assert isinstance(inp, str)

    resp = {}
    aliases = {'btc': 'bitcoin',
               'bch': 'bitcoin-cash',
               'bcc': 'bitcoin-cash',
               'bitcoin-sv': 'bitcoin-cash',
               'bsv': 'bitcoin-cash',
               'ltc': 'litecoin'}

    inp = inp.lower()
    network = inp.split(":")[0]
    if network:
        inp = ":".join(inp.split(":")[1:])
        network = aliases[network] if network in aliases else network
        network = network if network in CONF['networks'] else None
    if not network:
        network = "bitcoin"
        resp['warning'] = "Network not recognized, using BTC"

    if ":" in inp:
        port = inp.split(":")[-1]
        try:
            port = int(port)
            inp = ":".join(inp.split(":")[:-1])
        except ValueError:
            resp['warning'] = "port not recognized, using default"
            port = int(CONF['networks'][network]['port'])
    else:
        port = int(CONF['networks'][network]['port'])

    return network, inp, port, resp


@app.route('/api/check_node', methods=['POST'])
@auto.doc()
def check_node():
    """
    Checks the current status of a node. This is a live result, so response times will be longer - to view a saved
    result see /api/check_historic_node.
    :param node: connection string, e.g. btc:127.0.0.1:8333 - port is optional if it is the network default
    :param to_services (integer, optional): outgoing services to broadcast, default=0
    :param from_services (integer, optional): outgoing services to broadcast, default=0
    :param version (integer, optional): version code to broadcast, default varies by network
    :param user_agent (string, optional): user agent to broadcast, default="/open-nodes:0.1/"
    :param height (integer, optional): block height to broadcast during handshake. default=network median
    :param p2p_nodes (bool, optional): issues a getaddr call and list of connected nodes, default=False
    :return: json dict {"result":{"user_agent":"/satoshi:17.0.1/", "version":" .... }, "nodes":[["127.0.0.1:8333, 157532132191], ...]}
    """

    dat = request.form
    node = dat.get("node")
    network, address, port, resp = deconstruct_address_string(node)

    network_data = CONF['networks'][network]
    if dat.get("height"):
        network_data['height'] = dat.get("height")
    else:
        with open("static/network_summaries.json", 'r') as f:
            network_data['height'] = int(json.load(f)[network]['med'])

    network_data['protocol_version'] = dat.get("version") or network_data['protocol_version']
    result = connect(network, address, port,
                     to_services=dat.get("to_services") or network_data['services'],
                     network_data=network_data,
                     user_agent=dat.get("user_agent") or None,
                     p2p_nodes=False,
                     explicit_p2p=dat.get("p2p_nodes") or False,
                     from_services=dat.get('from_services') or None,
                     keepalive=False)

    resp['result'] = result[0]
    resp['nodes'] = result[1]

    resp['result'] = geocode(resp['result'])
    return to_json(resp)


@app.route('/api/check_historic_node', methods=['POST', 'GET'])
@auto.doc()
def check_historic_node():
    """
    Checks the status of a node based on the last crawl
    result see /api/check_historical_node
    :param node: connection string, e.g. btc:127.0.0.1:8333 - port is optional if it is the network default    
    :return: json dict {"result":{"user_agent":"/satoshi:17.0.1/", "version":" .... }}
    """

    if request.method == "POST":
        dat = request.form
    else:
        dat = request.args
    node = dat.get("node")

    network, address, port, resp = deconstruct_address_string(node)

    if network not in CONF['networks']:
        return json.dumps({'error': "network not recognized"})

    result = db.session.query(Node).get((network, address, port))
    resp['result'] = "None" if result is None else result.to_dict()

    return to_json(resp)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/api_docs")
def api_docs():
    return auto.html()


@app.route('/api/get_nodes', methods=['POST'])
@auto.doc()
def get_node_list():
    """
    Gets a list of all nodes visible during the past 30 days
    :param network (optional): Filters the result set based on the given network
    :return: json array [{"address":"127.0.0.1" ... }, {"address":"0.0.0.0", "port:8333}]
    """

    q = db.session.query(Node.network, Node.address, Node.port, Node.user_agent, Node.version, Node.first_seen,
                         Node.last_seen, Node.last_checked, Node.country, Node.city, Node.asn, Node.aso).filter(
        Node.seen)
    if request.args.get("network") is not None:
        network = request.args.get("network")
        if network not in CONF['networks']:
            return {"error": "network must be one of " + ", ".join(CONF['networks'])}
        q = q.filter(Node.network == network)
    return pd.read_sql(q.statement, q.session.bind).to_json(orient='records')

@app.route('/api/get_dash_masternodes', methods=['POST'])
@auto.doc()
def get_dash_masternodes():
    """
    Returns a list of all active dash masternodes - requires running dashd service on target server
    :return: json array ["45.76.112.193:9999", "206.189.110.182:9999", ...]
    """
    if not os.path.isfile(os.path.join("static","masternode_list.txt")):
        return json.dumps(list(update_masternode_list()))
    else:
        with open(os.path.join("static","masternode_list.txt"), "r") as f:
            return json.dumps(f.read().splitlines(keepends=False))

@app.route('/api/node_history', methods=['POST'])
@auto.doc()
def get_node_history():
    """
    Returns the data associated with a node, and all crawler visitations on record
    :param node: connection string, e.g. btc:127.0.0.1:8333 - port is optional if it is the network default.
    :return: json dict {"node":{"user_agent":"/Satoshi/", "last_seen": ... }, "history":{"timestamp":157032190321,"height":56000, "success":1 ...}}
    """


    node = request.form.get("node")

    network, address, port, resp = deconstruct_address_string(node)

    if network not in CONF['networks']:
        return json.dumps({'error': "network not recognized"})

    default_port = int(CONF['networks'][network]['port'])

    resp = {}

    try:
        port = int(port) if port is not None else default_port
    except ValueError:
        resp['warning'] = "port not recognized, using default"
        port = default_port

    n = db.session.query(Node.network, Node.address, Node.port, Node.user_agent, Node.version, Node.first_seen,
                         Node.last_seen, Node.last_checked, Node.country, Node.city, Node.asn, Node.aso) \
        .filter(and_(Node.network == network, Node.address == address, Node.port == port)).one()

    q = db.session.query(NodeVisitation.timestamp, NodeVisitation.height, NodeVisitation.success) \
        .join(Node, and_(Node.network == NodeVisitation.network, Node.address == NodeVisitation.address,
                         Node.port == NodeVisitation.port)) \
        .filter(and_(Node.network == network, Node.address == address, Node.port == port)) \
        .order_by(NodeVisitation.timestamp.desc())

    df = pd.read_sql(q.statement, q.session.bind)
    df['timestamp'] = df['timestamp'].astype(pd.np.int64) // 10 ** 9

    resp.update({"node": {"network": n.network, 'address': n.address, "port": n.port, "user_agent": n.user_agent,
                          "version": n.version,
                          "first_seen": n.first_seen,
                          "last_seen": n.last_seen,
                          "last_checked": n.last_checked,
                          "country": n.country, "city": n.city, "asn": n.asn, "aso": n.aso},
                 "history": df.to_dict(orient='records')})
    return to_json(resp)


def geocode(result):
    if result and result['address'].endswith('.onion'):
        aso, asn, country, city = "Anonymous", "Anonymous", "Anonymous", "Anonymous"
    elif result:
        try:
            aso = ASN.asn(result['address']).autonomous_system_organization
            asn = ASN.asn(result['address']).autonomous_system_number
        except AddressNotFoundError:
            aso = None
            asn = None

        try:
            country = COUNTRY.country(result['address']).country.name
        except AddressNotFoundError:
            country = None

        try:
            city = CITY.city(result['address']).city.name
        except AddressNotFoundError:
            city = None
    else:
        return result

    result['aso'] = aso
    result['asn'] = asn
    result['country'] = country
    result['city'] = city
    return result


def clean_dates(d):
    for i in d:
        if isinstance(d[i], datetime.datetime):
            d[i] = d[i].timestamp()
        if isinstance(d[i], dict):
            d[i] = clean_dates(d[i])
    return d


def to_json(d):
    """
    Sanitizes a dictionary - converts datetime.datetime instances to timestamps
    :param d: dictionary
    :return: json string
    """
    d = clean_dates(d)
    return json.dumps(d)





def main():
    app.run("0.0.0.0", debug=False if "--prod" in sys.argv else True, port=8888 if "--prod" in sys.argv else 5000)

if __name__ == '__main__':
    main()
