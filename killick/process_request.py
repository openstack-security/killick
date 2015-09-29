import logging
import json
import pecan

from anchor import auth
from anchor import jsonloader
from anchor import validation
from anchor.X509 import signing_request

from killick import request
from killick import util

logger = logging.getLogger(__name__)

def recieve_csr(pecan_request):

    # Check Auth
    auth_result = auth.validate("default",
                                "myusername",
                                "simplepassword")

    # Parse and validate CSR
    new_request = _parse_csr(pecan_request, auth_result,
                             pecan_request.POST.get('user'))

    logger.info("Certificate Request validated, result: %s ",
                new_request.toInfoString())

    return_str = "Certificate Request Recieved. ID: %d\n" % new_request.request_id

    # If auto_deny when validation fails is enabled, deny cert
    if (jsonloader.conf.ra_options["auto_deny_if_validation_fails"] == "True") & (new_request.Valid is False):
        new_request.Denied = True
        return_str += "Certificate Request Denied Automatically\n"

    # If user notification of validation is enabled, add info
    if jsonloader.conf.ra_options["notify_user_validation_result"] == "True":
        return_str += "%s\n" % new_request.toInfoString()
        if new_request.Valid is False:
            return_str += new_request.validationResultToString()

    # write request to 'database'
    with open(jsonloader.conf.ra_options["certdb_file"], 'ab') as fout:
        fout.write(new_request.serialize())

    return return_str


def _parse_csr(pecan_request, auth_result, user):

    # Create requset object for writing to database
    new_request = request.request(pecan_request.POST.get('csr').replace("\n",""), util.get_next_id(jsonloader.conf.ra_options["certdb_file"]), user)

    #Parse csr for validation
    parsed_csr = None
    try:
        parsed_csr = signing_request.X509Csr.from_buffer(pecan_request.POST.get('csr'))
    except Exception as e:
        logger.exception("Exception while parsing the CSR: %s", e)
        pecan.abort(400, "CSR cannot be parsed") # Hack

    # Validate CSR
    try:
        new_request.validator_results = validation.validate_csr(jsonloader.conf.ra_options["ra_name"], auth_result, parsed_csr, pecan_request)
    except Exception as e:
        logger.exception("Error running validators: %s", e)
        pecan.abort(500, "Internal Validation Error")

    new_request.Valid = all(list(new_request.validator_results.values()))

    return new_request
