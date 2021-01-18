#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2018 Opennodes / blakebjorn
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import validates, sessionmaker
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Index, BIGINT, create_engine
import datetime

import config

Base = declarative_base()


class Node(Base):
    __tablename__ = 'nodes'

    id = Column(Integer, primary_key=True)
    network = Column(String(20), nullable=False)
    address = Column(String(50), nullable=False)
    port = Column(Integer, nullable=False)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    first_checked = Column(DateTime, nullable=True)
    last_checked = Column(DateTime, nullable=True)
    seen = Column(Boolean, default=False, nullable=False)
    last_height = Column(BIGINT, nullable=True)
    version = Column(Integer, nullable=True)
    user_agent = Column(String(75), nullable=True)
    services = Column(BIGINT, default=0, nullable=False)
    country = Column(String(60), nullable=True)
    city = Column(String(60), nullable=True)
    asn = Column(Integer, nullable=True)
    aso = Column(String(100), nullable=True)
    is_masternode = Column(Boolean, default=False, nullable=False)

    Index('idx_node', 'network', 'address', 'port', unique=True)

    def to_dict(self):
        return {
            "id": self.id,
            "network": self.network,
            "address": self.address,
            "port": self.port,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "first_checked": self.first_checked,
            "last_checked": self.last_checked,
            "seen": self.seen,
            "last_height": self.last_height,
            "version": self.version,
            "user_agent": self.user_agent,
            "services": self.services,
            "country": self.country,
            "city": self.city,
            "asn": self.asn,
            "aso": self.aso,
            "is_masternode": self.is_masternode
        }

    def from_dict(self, d):
        self.id = d['id']
        self.network = d["network"]
        self.address = d["address"]
        self.port = d['port']
        self.first_seen = d["first_seen"]
        self.last_seen = d["last_seen"]
        self.first_checked = d['first_checked']
        self.last_checked = d["last_checked"]
        self.seen = d["seen"]
        self.last_height = d["last_height"]
        self.version = d["version"]
        self.user_agent = d["user_agent"]
        self.services = d["services"]
        self.country = d['country']
        self.city = d['city']
        self.asn = d['asn']
        self.aso = d['aso']
        self.is_masternode = d['is_masternode']

    @staticmethod
    def new_from_dict(d):
        obj = Node()
        obj.id = d['id'] if 'id' in d else None
        obj.network = d["network"] if "network" in d else None
        obj.address = d["address"] if "address" in d else None
        obj.port = d['port'] if 'port' in d else None
        obj.first_seen = d["first_seen"] if "first_seen" in d else None
        obj.last_seen = d["last_seen"] if "last_seen" in d else None
        obj.first_checked = d['first_checked'] if "first_checked" in d else None
        obj.last_checked = d["last_checked"] if "last_checked" in d else None
        obj.seen = d["seen"] if "seen" in d else None
        obj.last_height = d["last_height"] if "last_height" in d else None
        obj.version = d["version"] if "version" in d else None
        obj.user_agent = d["user_agent"] if "user_agent" in d else None
        obj.services = d["services"] if "services" in d else None
        obj.country = d['country'] if 'country' in d else None
        obj.city = d['city'] if 'city' in d else None
        obj.asn = d['asn'] if 'asn' in d else None
        obj.aso = d['aso'] if 'aso' in d else None
        obj.is_masternode = d['is_masternode'] if 'is_masternode' in d else None
        return obj

    def __repr__(self):
        return "<NODE - {}>".format(self.to_dict())

    @validates('port', 'last_height', 'services', 'version', 'asn')
    def validate_integers(self, key, field):
        if field is not None:
            if field > 9223372036854775807:
                print("{}:{} is > SQLite Max Value. Truncating".format(key, field))
                return 9223372036854775807
            return int(field)
        return None

    @validates('address', 'user_agent', 'country', 'city', 'aso')
    def validate_string(self, key, field):
        if field is not None:
            if key == 'address':
                if len(field) > 50:
                    print(key, field, "over max len")
                    return field[:50]
            elif key == "aso":
                if len(field) > 100:
                    print(key, field, "over max len")
                    return field[:100]
            elif key == "user_agent":
                if len(field) > 75:
                    print(key, field, "over max len")
                    return field[:75]
            elif len(field) > 60:
                print(key, field, "over max len")
                return field[:60]
        return field


class CrawlSummary(Base):
    __tablename__ = 'crawl_summaries'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow())
    network = Column(String(255), nullable=False)
    node_count = Column(Integer, nullable=False)
    masternode_count = Column(Integer, nullable=False)
    lookback_hours = Column(Integer)

    def __repr__(self):
        return "<SUMMARY - {}:{}; {} ({} masternodes), {} hours>".format(
            self.network, self.timestamp.isoformat(), self.node_count, self.masternode_count, self.lookback_hours)


class UserAgent(Base):
    __tablename__ = 'user_agents'

    id = Column(Integer, primary_key=True)
    user_agent = Column(String(60))

    Index('idx_user_agent', 'user_agent')


class NodeVisitation(Base):
    __tablename__ = 'node_visitations'

    id = Column(Integer, primary_key=True)
    parent_id = Column(Integer)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow())
    success = Column(Boolean, default=False)
    height = Column(BIGINT, nullable=True)
    user_agent_id = Column(Integer)
    is_masternode = Column(Boolean, default=None)

    Index('idx_vis_timestamp', 'timestamp')

    def to_dict(self):
        return {
            "id": self.id,
            "parent_id": self.parent_id,
            "timestamp": self.timestamp,
            "success": self.success,
            "user_agent_id": self.user_agent_id,
            "is_masternode": self.is_masternode,
            "height": self.height
        }

    def from_dict(self, d):
        self.id = d['id']
        self.parent_id = d['parent_id']
        self.timestamp = d["timestamp"]
        self.success = d["success"]
        self.height = d["height"]
        self.is_masternode = d['is_masternode']
        self.user_agent_id = d['user_agent_id']

    @staticmethod
    def new_from_dict(d):
        obj = NodeVisitation()
        obj.id = d['id'] if 'id' in d else None
        obj.parent_id = d['parent_id'] if 'parent_id' in d else None
        obj.timestamp = d["timestamp"] if 'timestamp' in d else None
        obj.success = d["success"] if 'success' in d else None
        obj.height = d["height"] if 'height' in d else None
        obj.is_masternode = d['is_masternode'] if 'is_masternode' in d else None
        obj.user_agent_id = d['user_agent_id'] if 'user_agent_id' in d else None
        return obj

    @validates('user_agent')
    def validate_string(self, key, field):
        if field is not None and len(field) > 60:
            print(key, field, "over max len")
            return field[:60]
        return field

    def __repr__(self):
        return "<CHECK - {}:{};{} - {}>".format(self.network, self.address, self.port, self.success)


def init_db():
    if "sqlite:/" in config.DATABASE_URI:
        engine = create_engine(config.DATABASE_URI, connect_args={'timeout': 15}, echo=False)
    else:
        engine = create_engine(config.DATABASE_URI, echo=False)
    Base.metadata.create_all(engine)
    Sess = sessionmaker(bind=engine, autoflush=False)
    return Sess()


session = init_db()
