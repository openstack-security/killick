import json
import logging

from killick import request

logger = logging.getLogger(__name__)

def loadDB(dbfilepath):
    requestdb = {}
    line_counter = 0
    try:
        with open(dbfilepath, 'r') as fp:
            for line in fp:
                line_counter += 1
                req = request.request()
                req.fromjson(json.loads(line))
                requestdb[req.request_id] = req
        return requestdb
    except:
        logger.error("Error parsing json from: %s at line %d",dbfilepath,line_counter)


def writeDB(dbdata, dbfilepath):
    with open(dbfilepath, 'wb') as fout:
        for key in dbdata:
            fout.write(dbdata[key].serialize())

def get_next_id(dbfilepath):
    # hack
    requestdb = loadDB(dbfilepath)
    return max(requestdb.keys()) + 1
