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
    except IOError:
        logger.error("Cannot open certdb at %s, assuming no file and attempting to write anyway", dbfilepath)
        return {}
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
    if len(requestdb) == 0:
        # empty database file
        return 1
    else:
        return max(requestdb.keys()) + 1
