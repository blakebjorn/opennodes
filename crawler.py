"""
Open Nodes Crawler
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

import datetime
import json
import logging
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import numpy as np
import pandas as pd
import requests
from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError
from sqlalchemy import and_, or_, func, not_, case

from config import load_config
from models import Node, NodeVisitation, CrawlSummary, UserAgent, session
from protocol import ProtocolError, Connection, ConnectionError, Keepalive

logging.basicConfig(level=logging.INFO)

CONF = load_config()
ASN = Reader("geoip/GeoLite2-ASN.mmdb")
COUNTRY = Reader("geoip/GeoLite2-Country.mmdb")
CITY = Reader("geoip/GeoLite2-City.mmdb")
RENAMED_COUNTRIES = {"South Korea": "Republic of Korea"}
USER_AGENTS = {}


def get_user_agent_id(user_agent):
    user_agent = str(user_agent)
    if len(user_agent) > 60:
        user_agent = user_agent[:60]
    if user_agent not in USER_AGENTS:
        u = session.query(UserAgent).filter(UserAgent.user_agent == user_agent).first()
        if u is None:
            u = UserAgent(user_agent=user_agent)
            session.add(u)
            session.flush()
            logging.info(f"New User Agent > {u.id} {u.user_agent}")
        USER_AGENTS[str(user_agent)] = int(u.id)
    return USER_AGENTS[user_agent]


def connect(network, address, port, to_services, network_data, user_agent=None, explicit_p2p=False, p2p_nodes=True,
            from_services=None, keepalive=False, attempt=1):
    results = {'network': network, 'address': address, 'port': port,
               'timestamp': datetime.datetime.utcnow(), 'seen': 0, 'attempt': attempt}

    try:
        handshake_msgs = []
        new_addrs = []

        proxy = CONF['tor_proxy'] if address.endswith(".onion") else None

        conn = Connection((address, port),
                          (CONF['source_address'], 0),
                          magic_number=network_data['magic_number'],
                          socket_timeout=CONF['socket_timeout'],
                          proxy=proxy,
                          protocol_version=int(network_data['protocol_version']),
                          min_protocol_version=network_data['min_protocol_version'],
                          to_services=int(to_services),
                          from_services=int(from_services or network_data['services']),
                          user_agent=user_agent or CONF['user_agent'],
                          height=int(network_data['height']),
                          relay=CONF['relay'])

        try:
            conn.open()
        except (ProtocolError, ConnectionError, socket.error) as err:
            results['error'] = str(err)
            logging.debug("connection failed %s %s", type(err), err)
        else:
            try:
                handshake_msgs = conn.handshake()
                assert handshake_msgs
                results['seen'] = 1
                results['height'] = int(handshake_msgs[0]['height'])
                results['version'] = int(handshake_msgs[0]['version'])
                results['user_agent'] = handshake_msgs[0]['user_agent'].decode()
                results['services'] = int(handshake_msgs[0]['services'])
            except (ProtocolError, ConnectionError, socket.error, AssertionError) as err:
                results['error'] = str(err)
                logging.debug("handshake failed %s", err)

            msgs = []
            if len(handshake_msgs) > 0 and (p2p_nodes or explicit_p2p):
                getaddr = True
                chance = CONF['getaddr_prop']
                if chance < 1.0 and p2p_nodes and not explicit_p2p and "--seed" not in sys.argv:
                    if np.random.rand() > chance:
                        getaddr = False

                if getaddr:
                    try:
                        conn.getaddr(block=False)
                        msgs = msgs + conn.get_messages(commands=[b"addr"])
                        time.sleep(5)
                        msgs = msgs + conn.get_messages(commands=[b"addr"])
                    except (ProtocolError, ConnectionError, socket.error) as err:
                        logging.debug("getaddr failed %s", err)
            if keepalive:
                Keepalive(conn, 10).keepalive(addr=True if p2p_nodes else False)
            for msg in msgs:
                if msg['count'] > 1:
                    ts = results['timestamp'].timestamp()
                    for addr in msg['addr_list']:
                        if ts - addr['timestamp'] < 12 * 60 * 60:  # within 6 hours
                            new_addrs.append(addr)
        conn.close()
        return results, new_addrs
    except Exception as err:
        logging.warning("unspecified connection error: %s", err)
        return {}, []


def get_seeds(port, dns_seeds, address_seeds, default_services=0):
    """
    Initializes a list of reachable nodes from DNS seeders and hardcoded nodes to bootstrap the crawler.
    """
    export_list = []
    for seeder in dns_seeds:
        nodes = []

        try:
            ipv4_nodes = socket.getaddrinfo(seeder, None, socket.AF_INET)
        except socket.gaierror:
            if CONF['ipv6']:
                try:
                    ipv6_nodes = socket.getaddrinfo(seeder, None, socket.AF_INET6)
                except socket.gaierror as err:
                    logging.warning("%s %s", seeder, err)
                else:
                    nodes.extend(ipv6_nodes)
        else:
            nodes.extend(ipv4_nodes)

        for node in nodes:
            address = node[-1][0]
            export_list.append((address, port, default_services))

    for address in address_seeds:
        export_list.append((address, port, default_services))

    return export_list


def init_crawler(networks):
    # Populates list of all known node addresses and block heights
    db_networks = [x[0] for x in session.query(Node.network).distinct().all()]
    node_addresses = {}
    recent_heights = {}
    for network in set(db_networks + networks):
        node_addresses[network] = {f"{y.address};{y.port}" for y in
                                   session.query(Node.address, Node.port).filter(Node.network == network).all()}
        count = session.query(Node).filter(and_(Node.network == network, Node.last_height != None)).count()
        if count > 0:
            median = session.query(Node.last_height).filter(and_(Node.network == network, Node.last_height != None)) \
                .order_by(Node.last_height).limit(1).offset(count // 2).one()[0]
            if median:
                recent_heights[network] = [median]
        if network not in recent_heights:
            recent_heights[network] = [500000]
    return node_addresses, recent_heights


def check_dns(network_data, node_addresses):
    nodes = []
    for network in network_data:
        nc = network_data[network]
        dns_node_addrs = get_seeds(nc['port'], nc['dns_seeds'], nc['address_seeds'], default_services=nc['services'])
        for nodeAddr in dns_node_addrs:
            if nodeAddr[0] and nodeAddr[1]:
                if not f"{nodeAddr[0]};{nodeAddr[1]}" in node_addresses[network]:
                    node_addresses[network].add(f"{nodeAddr[0]};{nodeAddr[1]}")
                    new_node = Node(network=network, address=nodeAddr[0],
                                    port=int(nodeAddr[1]), services=int(nodeAddr[2]))
                    nodes.append(new_node)
    return nodes


def prune_nodes():
    # prune old nodes that can't be reached
    pruned = session.query(Node) \
        .filter(
        and_(
            Node.last_seen == None, Node.first_checked != None,
            Node.first_checked <= datetime.datetime.utcnow() - datetime.timedelta(days=CONF['min_pruning_age'])
        )).delete()

    if pruned > 0:
        logging.info(f"Pruned {pruned} nodes")

        # prune visitations that no longer have a parent node
        if CONF['prune_visitations']:
            deleted = session.query(NodeVisitation) \
                .outerjoin(Node, Node.id == NodeVisitation.parent_id) \
                .filter(Node.address == None).delete(synchronize_session=False)
            logging.info(f"{deleted} Visitations deleted")

        session.commit()


def calculate_pending_nodes(start_time):
    now = datetime.datetime.utcnow()
    # Get a list of all never checked nodes, and nodes that have been checked recently:
    q = session.query(Node)
    q = q.filter(or_(
        Node.first_checked == None,
        Node.last_checked == None,
        # Assume 30m interval
        # If it hasn't been seen before, check every 6h
        and_(Node.last_seen == None, Node.last_checked != None,
             Node.last_checked < now - datetime.timedelta(minutes=CONF['crawl_interval'] * 12)),
        # If it has been seen in the last 6 hours, check it every 30 minutes
        and_(Node.last_seen != None, Node.last_seen > now - datetime.timedelta(hours=6),
             Node.last_checked < now - datetime.timedelta(minutes=CONF['crawl_interval'])),
        # If it has been seen in the last 2 weeks, check it every 12 hours
        and_(Node.last_seen != None, Node.last_seen > now - datetime.timedelta(hours=24 * 14),
             Node.last_checked < now - datetime.timedelta(minutes=CONF['crawl_interval'] * 24)),
        # Otherwise every day
        and_(Node.last_seen != None,
             Node.last_checked < now - datetime.timedelta(minutes=CONF['crawl_interval'] * 48))
    )).filter(not_(and_(Node.last_checked != None, Node.last_checked > start_time)))

    if CONF['crawl_order']:
        case_order = []
        for i in range(len(CONF['crawl_order'])):
            case_order.append((Node.network == CONF['crawl_order'][i], str(i)))
        q = q.order_by(case(case_order, else_=Node.network), Node.seen.desc(), Node.last_checked)
    else:
        q = q.order_by(Node.seen.desc(), Node.last_checked)

    if CONF['max_queue'] > 0:
        count = q.count()
        q = q.limit(CONF['max_queue'])
    else:
        count = q.count()
    if count > CONF['max_queue']:
        logging.info(f"{count} nodes pending")

    if CONF['database_concurrency']:
        nodes = q.with_for_update().all()
        session.bulk_update_mappings(Node, [
            {'id': x.id, 'last_checked': now} for x in nodes])
        session.commit()
        return nodes

    return q.all()


def process_pending_nodes(node_addresses, node_processing_queue, recent_heights, thread_pool, mnodes=None):
    futures_dict = {}

    checked_nodes = 0
    seen_nodes = 0
    pending_nodes = 0
    skipped_nodes = 0
    retried_nodes = 0
    found_on_retry = 0
    new_nodes_to_add = []

    for net in recent_heights:
        CONF['networks'][net]['height'] = max(set(recent_heights[net]),
                                              key=recent_heights[net].count)
        recent_heights[net] = [CONF['networks'][net]['height']]

    # Get list of seen IPs and Ports so we don't send a bitcoin magic number to a bitcoin-cash node
    q = session.query(Node.network, Node.address, Node.port, Node.last_seen) \
        .filter(Node.last_seen > datetime.datetime.utcnow() - datetime.timedelta(days=3))

    active_ips = {}
    for x in q.all():
        key = x.address + "|" + str(x.port)
        if key not in active_ips:
            active_ips[key] = (x.network, x.last_seen)
        else:
            # Prioritize bitcoin cash nodes, as its the only client that bans when the wrong magic number is sent
            if x.network == "bitcoin-cash":
                active_ips[key] = (x.network, x.last_seen)
            elif x.last_seen > active_ips[key][1] and active_ips[key][0] != "bitcoin-cash":
                active_ips[key] = (x.network, x.last_seen)

    while node_processing_queue:
        node = node_processing_queue.pop(0)
        if f"{node.address}|{node.port}" in active_ips and \
                active_ips[f"{node.address}|{node.port}"][0] != node.network:
            node.last_checked = datetime.datetime.utcnow()
            session.add(node)
            skipped_nodes += 1
            continue
        future = thread_pool.submit(connect, node.network, node.address, node.port, node.services,
                                    CONF['networks'][node.network])
        futures_dict[f"{node.network}|{node.address}|{node.port}"] = node, future
        time.sleep(0.001)

    total_to_complete = len(futures_dict)

    while len(futures_dict) > 0:
        time.sleep(1)
        for i in list(futures_dict.keys()):
            if not futures_dict[i][1].done():
                continue

            checked_nodes += 1
            if checked_nodes % 1000 == 0:
                logging.info(f" {round(checked_nodes / total_to_complete * 100.0, 1)}%")

            node, future = futures_dict.pop(i)
            result, new_addrs = future.result()
            if not result:
                continue

            if not result['seen']:
                if CONF['retry_threshold'] and CONF['retry_threshold'] > 0 and (not node.seen or (
                        node.last_seen and node.last_seen < datetime.datetime.utcnow() -
                        datetime.timedelta(hours=CONF['retry_threshold']))):
                    pass
                elif result['attempt'] < CONF['retries'] + 1:
                    future = thread_pool.submit(connect, node.network, node.address, node.port, node.services,
                                                CONF['networks'][node.network], attempt=result['attempt'] + 1)
                    futures_dict[f"{node.network}|{node.address}|{node.port}"] = node, future
                    total_to_complete += 1
                    retried_nodes += 1
                    continue
            elif result['seen'] and result['attempt'] > 1:
                found_on_retry += 1

            x = result['timestamp']
            timestamp = datetime.datetime(x.year, x.month, x.day, x.hour, x.minute, x.second, x.microsecond)

            node.last_checked = timestamp
            if node.first_checked is None:
                node.first_checked = timestamp
            if result["seen"] and not any((x.match(result['user_agent']) for x in CONF['excluded_user_agents'])):
                node.version = result['version']
                node.last_seen = timestamp
                node.services = result['services']
                node.user_agent = result['user_agent']
                node.last_height = result['height']
                if node.first_seen is None:
                    node.first_seen = timestamp
                    node.country, node.city, node.aso, node.asn = geocode_ip(node.address)
                node.seen = True

                seen_nodes += 1
                recent_heights[result['network']].append(result['height'])

            session.add(node)

            if node.seen:
                if not node.id:
                    session.commit()
                vis = NodeVisitation(parent_id=node.id,
                                     user_agent_id=get_user_agent_id(result['user_agent'])
                                     if 'user_agent' in result else None,
                                     success=result["seen"],
                                     timestamp=timestamp,
                                     height=result['height'] if result["seen"] else None)

                if mnodes and node.network == "dash" and f"{node.address}:{node.port}" in mnodes:
                    vis.is_masternode = True

                session.add(vis)

            if new_addrs:
                for n in new_addrs:
                    addr = n['ipv4'] or n['ipv6'] or n['onion']
                    if not f"{addr};{n['port']}" in node_addresses[result['network']]:
                        pending_nodes += 1
                        node_addresses[result['network']].add(f"{addr};{n['port']}")
                        new_node = Node(network=str(result['network']), address=addr, port=int(n['port']),
                                        services=int(n['services']))
                        if CONF['database_concurrency']:
                            new_nodes_to_add.append(new_node)
                        else:
                            session.add(new_node)

    if CONF['database_concurrency']:
        # Get all unchecked nodes and nodes first seen in the past hour,
        # don't insert any new nodes that have already been inserted
        nn = session.query(Node.network, Node.address, Node.port) \
            .filter(or_(Node.first_checked == None,
                        Node.first_checked > datetime.datetime.utcnow() - datetime.timedelta(hours=1))) \
            .with_for_update().all()
        new_set = {f"{n.network};{n.address};{n.port}" for n in nn}
        for i in reversed(range(len(new_nodes_to_add))):
            ni = f"{new_nodes_to_add[i].network};{new_nodes_to_add[i].address};{new_nodes_to_add[i].port}"
            if ni in new_set:
                del new_nodes_to_add[i]

    session.commit()
    logging.info(f"Checked {checked_nodes - retried_nodes} Nodes, {seen_nodes} Seen, {pending_nodes} More queued up. "
                 f"({found_on_retry}/{retried_nodes} retry successes, {skipped_nodes} skipped x-network nodes)")
    return node_processing_queue, node_addresses


def update_masternode_list():
    if os.environ.get("DASH_RPC_URI"):
        resp = requests.post(os.environ.get("DASH_RPC_URI"),
                             json={"jsonrpc": "2.0", "id": "jsonrpc", "method": "masternode", "params": ["list"]},
                             auth=(os.environ.get("DASH_RPC_USER"), os.environ.get("DASH_RPC_PASS")))
        masternodes = resp.json()['result']
    else:
        comm = "dash-cli"
        if os.path.isdir(CONF['dash_cli_path']):
            comm = os.path.join(CONF['dash_cli_path'], "dash-cli")
        masternodes = os.popen(f"{comm} masternode list full").read().strip()
        masternodes = json.loads(masternodes)

    m_nodes = set()
    if masternodes:
        for i, vals in masternodes.items():
            if isinstance(vals, dict):
                address = vals['address']
            else:
                address = vals[-1]
            m_nodes.add(address.strip())

    if not masternodes and CONF['dash_masternodes_api']:
        try:
            m_nodes = set(requests.post(CONF['dash_masternodes_api']).json())
        except:
            pass

    if m_nodes:
        with open("static/masternode_list.txt", 'w') as f:
            f.write("\n".join(m_nodes))
    elif os.path.isfile("static/masternode_list.txt"):
        with open("static/masternode_list.txt", "r") as f:
            m_nodes = set(f.read().splitlines(keepends=False))
    return m_nodes


def set_master_nodes(m_nodes):
    if not m_nodes:
        return
    window_idx = 0
    window_size = 10000
    q = session.query(Node).filter(Node.seen == True)
    while True:
        start, stop = window_size * window_idx, window_size * (window_idx + 1)
        nodes = q.slice(start, stop).all()
        if nodes is None:
            break
        for n in nodes:
            if n.address + ":" + str(n.port) in m_nodes:
                n.is_masternode = True
                session.add(n)
            elif n.is_masternode:
                n.is_masternode = False
                session.add(n)
        session.commit()
        window_idx += 1
        if len(nodes) < window_size:
            break


def code_ip_type(inp):
    if ".onion" in inp:
        return "Onion"
    elif "." in inp:
        return "IPv4"
    elif ":" in inp:
        return "IPv6"
    else:
        return "Unknown"


def geocode_ip(address):
    aso = None
    asn = None
    country = None
    city = None
    if not address.endswith(".onion"):
        try:
            aso = ASN.asn(address).autonomous_system_organization
            asn = ASN.asn(address).autonomous_system_number
        except AddressNotFoundError:
            pass
        try:
            country = COUNTRY.country(address).country.name
            country = RENAMED_COUNTRIES.get(country, country)
            city = CITY.city(address).city.name
        except AddressNotFoundError:
            pass
    return country, city, aso, asn


def check_active(height, deviation_config):
    return (deviation_config[1] - deviation_config[0]) <= height <= (deviation_config[1] + deviation_config[0])


def dump_summary():
    # Set updated countries
    for n in session.query(Node).all():
        n.country, n.city, n.aso, n.asn = geocode_ip(n.address, )

    # Get and set dash masternodes
    if CONF['get_dash_masternodes']:
        mnodes = update_masternode_list()
        set_master_nodes(mnodes)
        logging.info("masternodes updated")

    q = session.query(Node.id, Node.network, Node.address, Node.port, Node.user_agent, Node.version, Node.asn, Node.aso,
                      Node.country, Node.city, Node.last_seen, Node.last_height, Node.is_masternode) \
        .filter(Node.seen == True) \
        .filter(Node.last_seen >= datetime.datetime.utcnow() - datetime.timedelta(days=7))

    nodes = pd.read_sql(q.statement, q.session.bind)
    nodes[['port', 'version', 'last_height']] = nodes[['port', 'version', 'last_height']].fillna(0)
    nodes = nodes.fillna("")

    if nodes.empty:
        logging.warning("Nodes table is empty, no results to dump")
        return

    # Exclude user agents
    if CONF['excluded_user_agents']:
        for agent_re in CONF['excluded_user_agents']:
            agent_re = re.compile(agent_re)
            nodes = nodes[~nodes['user_agent'].str.match(agent_re)].copy()

    now = datetime.datetime.utcnow()
    labels = []
    for age, label in [(2, "2h"), (8, "8h"), (24, "24h"), (24 * 7, "7d"), (24 * 30, "30d")]:
        stt = time.time()
        q = session.query(Node.id,
                          func.sum(case([(NodeVisitation.success, 1)], else_=0)).label("success"),
                          func.count(NodeVisitation.parent_id).label("total")) \
            .join(NodeVisitation, Node.id == NodeVisitation.parent_id) \
            .group_by(Node.id) \
            .filter(Node.last_seen > now - datetime.timedelta(hours=age)) \
            .filter(NodeVisitation.timestamp >= now - datetime.timedelta(hours=age))
        df = pd.read_sql(q.statement, q.session.bind)
        df[label] = (df['success'] / df['total']).fillna(0.0)
        nodes = nodes.merge(df[['id', label]], how="left")
        labels.append(label)
        logging.info(f"done {label} in {round(time.time() - stt, 3)}s")
    nodes = nodes.drop(['id'], 1)
    nodes[labels] = nodes[labels].fillna(0.0).round(3)
    nodes[['network', 'address']] = nodes[['network', 'address']].fillna("")
    nodes['address_type'] = nodes['address'].apply(code_ip_type)

    nodes['network'] = nodes[['network', 'user_agent']].apply(
        lambda x: "bitcoin-sv" if x['network'] == 'bitcoin-cash' and ' SV' in x['user_agent'] else x['network'], axis=1)

    networks = nodes['network'].unique()

    # Calculate summaries
    summaries = {}
    for network in networks:
        summary_df = nodes[(nodes['network'] == network) &
                           (nodes['last_seen'] > datetime.datetime.utcnow() - datetime.timedelta(
                               hours=8))]
        if summary_df.empty:
            continue

        summaries[network] = {
            "min": int(summary_df['last_height'].fillna(np.inf).min()),
            "max": int(summary_df['last_height'].fillna(0.0).max()),
            "mean": float(summary_df['last_height'].mean()),
            "stdev": float(summary_df['last_height'].std()),
            "med": float(summary_df['last_height'].median()),
            "1q": float(np.percentile(summary_df['last_height'], 25)),
            "3q": float(np.percentile(summary_df['last_height'], 75)),
            "2.5pct": float(np.percentile(summary_df['last_height'], 1)),
            "97.5pct": float(np.percentile(summary_df['last_height'], 99)),
            "age_min": nodes[nodes['network'] == network]['last_seen'].min().timestamp(),
            "age_max": summary_df['last_seen'].max().timestamp()
        }
        summaries[network]['iqr'] = summaries[network]['3q'] - summaries[network]['1q']
        summaries[network]['95_range'] = summaries[network]['97.5pct'] - summaries[network]['2.5pct']

    summaries["_timestamp"] = datetime.datetime.utcnow().isoformat()
    with open("static/network_summaries.json", 'w') as f:
        json.dump(summaries, f)

    if CONF['inactive_use_iqr']:
        deviations = {network: summaries[network]['iqr'] * (
            CONF['inactive_threshold'][network] if network in CONF['inactive_threshold'] else
            CONF['inactive_threshold']['default']) for network in networks}
    else:
        deviations = {net: CONF['inactive_threshold'][net] if net in CONF['inactive_threshold'] else \
            CONF['inactive_threshold']['default'] for net in networks}

    for i in deviations:
        deviations[i] = (deviations[i], summaries[i]['3q'])

    nodes['is_active'] = nodes[['network', 'last_height']] \
        .apply(lambda x: check_active(x['last_height'], deviations[x['network']]), axis=1)

    if not CONF['export_inactive_nodes']:
        nodes = nodes[nodes['is_active']].copy()

    nodes['last_seen'] = nodes['last_seen'].values.astype(np.int64) // 10 ** 9
    nodes.to_csv("static/data.csv", index=False)

    with open("static/data.txt", "w") as f:
        f.write(space_sep_df(nodes))

    for network in nodes['network'].unique():
        net_df = nodes[nodes['network'] == network].copy()
        net_df = net_df.drop(['network'], 1)

        net_df.to_csv(f"static/data_{network}.csv", index=False)
        with open(os.path.join("static", f"data_{network}.json"), "w") as f:
            json.dump({'data': net_df.to_dict(orient="records")}, f)
        with open(os.path.join("static", f"data_{network}.txt"), "w") as f:
            f.write(space_sep_df(net_df))

    nodes = nodes.drop(['user_agent', 'version', 'last_height'], 1)
    with open(os.path.join("static", "data.json"), "w") as f:
        json.dump({'data': nodes.to_dict(orient="records")}, f)

    # Write unique addresses only
    def group_nets(x):
        return ", ".join(sorted(set(x)))

    nodes = nodes.groupby(by=['address', 'asn', 'aso', 'country', 'city', 'address_type'], as_index=False).agg(
        {"network": group_nets, "2h": "mean", "8h": "mean", "24h": "mean", "7d": "mean", "30d": "mean"})
    nodes.to_csv("static/data_unique.csv", index=False)

    with open(os.path.join("static", "data_unique.json"), "w") as f:
        json.dump({'data': nodes.to_dict(orient="records")}, f)
    with open(os.path.join("static", "data_unique.txt"), "w") as f:
        f.write(space_sep_df(nodes))

    for network in networks:
        net_df = nodes[nodes['network'].str.contains(network)]
        net_df = net_df.drop(['network'], 1)
        net_df.to_csv(os.path.join("static", f"data_{network}_unique.csv"), index=False)
        with open(os.path.join("static", f"data_{network}_unique.json"), "w") as f:
            json.dump({'data': net_df.to_dict(orient="records")}, f)
        with open(os.path.join("static", f"data_{network}_unique.txt"), "w") as f:
            f.write(space_sep_df(net_df))


def space_sep_df(df, spacing=3):
    df = df.copy()
    df = pd.DataFrame([df.columns], columns=df.columns).append(df)
    for col in df.columns:
        df[col] = df[col].astype(str)
        max_len = df[col].str.len().max() + spacing
        df[col] = df[col].str.pad(max_len, side="right")
    out_str = "\n".join(("".join((str(row[x + 1]) for x in range(len(df.columns)))) for row in df.itertuples()))
    return out_str


def main(seed=False):
    start_time = datetime.datetime.utcnow()
    thread_pool = ThreadPoolExecutor(max_workers=CONF['threads'])
    networks = list(CONF['networks'].keys())
    prune_nodes()
    node_addresses, recent_heights = init_crawler(networks)

    if CONF['get_dash_masternodes']:
        mnodes = update_masternode_list()
    else:
        mnodes = None

    if seed:
        seed_nodes = check_dns(CONF['networks'], node_addresses)
        if seed_nodes:
            for n in seed_nodes:
                session.add(n)
        session.commit()

    node_processing_queue = calculate_pending_nodes(start_time)
    while node_processing_queue:
        node_processing_queue, node_addresses = process_pending_nodes(node_addresses, node_processing_queue,
                                                                      recent_heights, thread_pool, mnodes)
        node_processing_queue = calculate_pending_nodes(start_time)
    logging.info(f"Crawling complete in {round((datetime.datetime.utcnow() - start_time).seconds, 1)} seconds")


def dump():
    start_time = datetime.datetime.utcnow()
    dump_summary()
    generate_historic_data()
    logging.info(f"Results saved in {round((datetime.datetime.utcnow() - start_time).seconds, 1)} seconds")


def generate_historic_data():
    networks = [x[0] for x in session.query(Node.network).distinct()]
    sd = session.query(func.min(Node.first_seen)).one()[0]
    start_date = datetime.datetime(sd.year, sd.month, sd.day,
                                   sd.hour // CONF['historic_interval'] * CONF['historic_interval'], 0, 0)
    end_date = session.query(func.max(Node.last_seen)).one()[0]

    historic_interval = datetime.timedelta(hours=CONF['historic_interval'])

    last_date = start_date
    while last_date < end_date:
        last_date += historic_interval

    interval_end = start_date + historic_interval
    session.query(CrawlSummary).filter(
        CrawlSummary.timestamp >= (last_date - datetime.timedelta(hours=CONF['historic_interval'] * 1.5))).delete()
    session.commit()
    while interval_end < end_date:
        if session.query(CrawlSummary).filter(CrawlSummary.timestamp == interval_end).count() >= 1:
            interval_end += historic_interval
            continue
        logging.info(f"Summarizing period starting with {interval_end - historic_interval}")

        sv_sq = session.query(UserAgent.id).filter(UserAgent.user_agent.ilike("% SV%")).subquery()

        case_stmt = case([(sv_sq.c.id != None, 'bitcoin-sv')], else_=Node.network)

        q = session.query(NodeVisitation.parent_id.label("id"),
                          case_stmt.label("network"),
                          func.max(NodeVisitation.height).label("height"),
                          func.max(case([(NodeVisitation.is_masternode, 1)], else_=0)).label("is_masternode")) \
            .join(sv_sq, NodeVisitation.user_agent_id == sv_sq.c.id) \
            .join(Node, Node.id == NodeVisitation.parent_id) \
            .filter(NodeVisitation.timestamp >= interval_end - historic_interval) \
            .filter(NodeVisitation.timestamp <= interval_end) \
            .filter(NodeVisitation.success == True) \
            .filter(Node.first_seen <= interval_end) \
            .filter(Node.last_seen >= interval_end - historic_interval) \
            .group_by(NodeVisitation.parent_id, case_stmt)
        df = pd.read_sql(q.statement, q.session.bind)

        df['height'] = df['height'].astype(int)
        if not df.empty:
            networks = df['network'].unique()

            medians = df.groupby(by=['network']).agg({"height": "median"})
            deviations = {network: CONF['inactive_threshold'][network] if network in CONF['inactive_threshold'] else \
                CONF['inactive_threshold']['default'] for network in networks}

            for i in list(deviations.keys()):
                if i in medians.index:
                    deviations[i] = (deviations[i], medians.loc[i]['height'])
                else:
                    deviations.pop(i)

            df['active'] = df[['network', 'height']].apply(
                lambda x: check_active(x['height'], deviations[x['network']]), axis=1)
            df = df[df['active']].drop(['active'], 1)

        for network in networks:
            net_df = df[df['network'] == network]
            cs = CrawlSummary(timestamp=interval_end,
                              network=network,
                              node_count=len(net_df),
                              masternode_count=sum(net_df['is_masternode']),
                              lookback_hours=CONF['historic_interval'])

            session.add(cs)
            session.commit()

        interval_end += datetime.timedelta(hours=CONF['historic_interval'])

    q = session.query(CrawlSummary).order_by(CrawlSummary.timestamp)
    df = pd.read_sql(q.statement, q.session.bind)
    df['timestamp'] = df['timestamp'].values.astype(np.int64) // 10 ** 9

    for network in networks:
        df[df['network'] == network][['timestamp', 'node_count', 'masternode_count']] \
            .to_json(os.path.join("static", f"history_{network}.json"), orient='records')


def prune_database():
    if not os.path.isdir("db_cache"):
        os.mkdir("db_cache")

    q = session.query(Node)
    nodes = pd.read_sql(q.statement, q.session.bind)

    fv = session.query(func.min(NodeVisitation.timestamp)).first()[0]
    end_date = datetime.datetime.utcnow() - datetime.timedelta(hours=24 * CONF['max_pruning_age'])
    end_date = datetime.datetime(end_date.year, end_date.month, end_date.day, 0, 0, 0)

    current_date = datetime.datetime(fv.year, fv.month, fv.day, 0, 0, 0)
    current_end = current_date + datetime.timedelta(days=1)

    while current_end < end_date:
        vq = session.query(NodeVisitation) \
            .filter(NodeVisitation.timestamp >= current_date) \
            .filter(NodeVisitation.timestamp < current_end)

        f_name = f"visitations_{current_date.strftime('%Y-%m-%d')}.gz"
        f_name = os.path.join("db_cache", f_name)
        f_name_alt = f"nodes_{current_date.strftime('%Y-%m-%d')}.gz"
        f_name_alt = os.path.join("db_cache", f_name_alt)

        df = pd.read_sql(vq.statement, vq.session.bind)
        an = nodes.merge(df[['parent_id']].drop_duplicates(), left_on="id", right_on="parent_id")
        an = an[[x for x in an.columns if x != "parent_id"]]

        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['timestamp'] = df['timestamp'].astype(np.int64) / 1000000000
        df['height'] = df['height'].fillna(-1).apply(lambda x: int(x) if x > 0 else "")
        df['success'] = df['success'].fillna(-1).apply(lambda x: int(x) if x > 0 else "")
        df['user_agent_id'] = df['user_agent_id'].fillna(-1).apply(lambda x: int(x) if x > 0 else "")
        df['is_masternode'] = df['is_masternode'].fillna(-1).apply(lambda x: int(x) if x > 0 else "")
        df.to_csv(f_name, compression="gzip", index=False)

        for col in ("first_seen", "last_seen", "first_checked", "last_checked"):
            an[col] = pd.to_datetime(an[col])
            an[col] = an[col].astype(np.int64) / 1000000000
        for col in ("seen", "last_height", "version", "services", "is_masternode"):
            an[col] = an[col].apply(lambda x: int(x) if x else "")
        an.to_csv(f_name_alt, compression="gzip", index=False)

        deleted = vq.delete()
        session.commit()

        current_date = current_date + datetime.timedelta(days=1)
        current_end = current_date + datetime.timedelta(days=1)
        logging.info(f"pruned up to {current_end} // {deleted} visitations removed")


if __name__ == "__main__":

    if "--crawl" in sys.argv:
        main(seed=True if "--seed" in sys.argv else False)

    if "--dump" in sys.argv:
        dump()

    if "--prune" in sys.argv:
        prune_database()

    if "--daemon" in sys.argv:
        conf = CONF.get('daemon', {})
        crawl_interval = int(conf.get('crawl_interval', 15))
        dump_interval = int(conf.get('dump_interval', 60))
        prune_interval = conf.get('prune_interval', None)
        current = int(time.time())
        last_minutes = -1

        main(seed=True)
        dump()
        if prune_interval is not None:
            prune_database()
        while True:
            minutes = int(current / 60)
            if minutes != last_minutes:
                last_minutes = minutes
                if minutes % crawl_interval == 0:
                    main(seed=False)
                if minutes % dump_interval == 0:
                    dump()
                if prune_interval is not None and minutes % int(prune_interval) == 0:
                    prune_database()

            current += 1
            while current > time.time():
                time.sleep(0.1)
