# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import

import json
import logging

from anchor import jsonloader

from killick import request
from killick import util

logger = logging.getLogger(__name__)
logging.basicConfig()

def list(*filter):
    jsonloader.conf.load_file_data("config.json")
    dbdata = util.loadDB(jsonloader.conf.ra["certdb_file"])
    return_str = ""
    if len(filter) > 0:
        return_str += "filtering on %s\n" % filter[0]
        if filter[0].lower() == "issued":
            for req in sorted(dbdata):
                if dbdata[req] is None:
                    continue
                if dbdata[req].getStatus() == "Issued":
                    return_str += dbdata[req].toInfoString() + "\n"
        elif filter[0].lower() == "revoked":
            for req in sorted(dbdata):
                if dbdata[req] is None:
                    continue
                if req.getStatus() == "Revoked":
                    return_str += dbdata[req].toInfoString() + "\n"

        elif filter[0].lower() == "denied":
            for req in sorted(dbdata):
                if dbdata[req] is None:
                    continue
                if dbdata[req].getStatus() == "Denied":
                    return_str += dbdata[req].toInfoString() + "\n"
        elif filter[0].lower() == "pending":
            for req in sorted(dbdata):
                if dbdata[req] is None:
                    continue
                if dbdata[req].getStatus() == "Pending":
                    return_str += dbdata[req].toInfoString() + "\n"
        else:
            return_str = "Unkown filter, valid filters are issued, pending, denied or revoked"
    else:
        for req in sorted(dbdata):
            if dbdata[req] is None:
                continue
            return_str += dbdata[req].toInfoString() + "\n"

    return return_str


def issue(reqid):
    jsonloader.conf.load_file_data("config.json")
    dbdata = util.loadDB(jsonloader.conf.ra["certdb_file"])
    try:
        if dbdata[reqid].getStatus() == "Pending":
            dbdata[reqid].Issued = True
        elif dbdata[reqid].getStatus() == "Issued":
            return "Cannot issue, certificate already Issued"
        elif dbdata[reqid].getStatus() == "Denied":
            return "Cannot issue certificate already Denied"
        elif dbdata[reqid].getStatus() == "Revoked":
            return "Cannot issue certificate already Revoked"
        util.writeDB(dbdata, jsonloader.conf.ra["certdb_file"])
        return dbdata[reqid].toInfoString()
    except:
        return "Cannot find reqid %d in cert DB" % reqid


def revoke(reqid):
    jsonloader.conf.load_file_data("config.json")
    dbdata = util.loadDB(jsonloader.conf.ra["certdb_file"])
    try:
        if dbdata[reqid].getStatus() == "Revoked":
            return "Cannot revoke, certificate already Revoked"
        elif dbdata[reqid].getStatus() == "Issued":
            dbdata[reqid].Revoked = True
        elif dbdata[reqid].getStatus() == "Pending":
            return "Cannot revoke, certificate not Issued"
        elif dbdata[reqid].getStatus() == "Denied":
            return "Cannot revoke, certificate already Denied"
        else:
            return "Cannot revoke, Unkown state error"
        util.writeDB(dbdata, jsonloader.conf.ra["certdb_file"])
        return dbdata[reqid].toInfoString()
    except:
        return "Cannot find reqid %d in cert DB" % reqid


def deny(reqid):
    jsonloader.conf.load_file_data("config.json")
    dbdata = util.loadDB(jsonloader.conf.ra["certdb_file"])
    try:
        if dbdata[reqid].getStatus() == "Revoked":
            return "Cannot deny, certificate already Revoked"
        elif dbdata[reqid].getStatus() == "Issued":
            return "Cannot deny, certificate already Issued"
        elif dbdata[reqid].getStatus() == "Pending":
            dbdata[reqid].Denied = True
        elif dbdata[reqid].getStatus() == "Denied":
            return "Cannot deny, certificate already Denied"
        else:
            return "Cannot deny, Unkown state error"
        util.writeDB(dbdata, jsonloader.conf.ra["certdb_file"])
        return dbdata[reqid].toInfoString()
    except:
        return "Cannot find reqid %d in cert DB" % reqid

def info(reqid):
    jsonloader.conf.load_file_data("config.json")
    dbdata = util.loadDB(jsonloader.conf.ra["certdb_file"])
    try:
        return_str = dbdata[reqid].toInfoString() + "\n"
        return_str += dbdata[reqid].validationResultToString() + "\n"
        return return_str
    except:
        return "Cannot find reqid %d in cert DB" % reqid

def processCommand(jsonmsg):
    #  Process Command recieved via http put of json.
    #    method: [issue|revoke|deny]
    #    reqid: [int cert id]

    try:
        cmd = json.loads(jsonmsg)
        if str(cmd["method"]).lower() == "issue":
            print "Issuing %d" % cmd["reqid"]
            print issue(cmd["reqid"])
        elif str(cmd["method"]).lower() == "deny":
            print "Dening %d" % cmd["reqid"]
            print deny(cmd["reqid"])
        elif str(cmd["method"]).lower() == "revoke":
            print "Revoking %d" % cmd["reqid"]
            print revoke(cmd["reqid"])
        else:
            print "Unkown command"
    except:
        return "Cannot parse json command %s\n" % jsonmsg
