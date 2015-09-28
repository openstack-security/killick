import logging
import json

from anchor import jsonloader

from killick import request
from killick import util

logger = logging.getLogger(__name__)

def recieve_csr(input_csr, user):

    jsonloader.conf.load_file_data("config.json") # todo tidy conf loading

    new_request = request.request(input_csr.replace("\n",""), util.get_next_id(jsonloader.conf.ra["certdb_file"]))
    new_request.user = user
    new_request.validator_results = {"validator1": False, "validator2": True} # waiting for tim
    new_request.Valid = all(new_request.validator_results.values())

    logger.info("Certificate Request validated, result: %s ",
                new_request.toInfoString())

    return_str = "Certificate Request Recieved. ID: %d\n" % new_request.request_id

    # If auto_deny when validation fails is enabled, deny cert
    if (jsonloader.conf.ra["auto_deny_if_validation_fails"] == "True") & (new_request.Valid is False):
        new_request.Denied = True
        return_str += "Certificate Request Denied Automatically\n"

    # If user notification of validation is enabled, add info
    if jsonloader.conf.ra["notify_user_validation_result"] == "True":
        return_str += "%s\n" % new_request.toInfoString()
        if new_request.Valid is False:
            return_str += new_request.validationResultToString()

    # write request to 'database'
    with open(jsonloader.conf.ra["certdb_file"], 'ab') as fout:
        fout.write(new_request.serialize())

    return return_str
