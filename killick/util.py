import json
import logging

from killick import request

logger = logging.getLogger(__name__)


def load_db(dbfilepath):
    requestdb = {}
    line_counter = 0
    try:
        with open(dbfilepath, 'r') as fp:
            for line in fp:
                line_counter += 1
                req = request.request(None, None, None)
                req.fromjson(json.loads(line))
                requestdb[req.request_id] = req
        return requestdb
    except Exception:
        logger.error("Error parsing json from: %s at line %d",
                     dbfilepath, line_counter)


def write_db(dbdata, dbfilepath):
    with open(dbfilepath, 'wb') as fout:
        for key in dbdata:
            fout.write(dbdata[key].serialize())


def get_next_id(dbfilepath):
    # hack
    requestdb = load_db(dbfilepath)
    return max(requestdb.keys()) + 1
