import logging

from anchor import auth
from anchor import jsonloader
from anchor import validation
import pecan

from killick import request
from killick import util

logger = logging.getLogger(__name__)


def _parse_csr(pecan_request, auth_result, user):

    # Create request object for writing to database
    new_request = request.request(pecan_request.POST.get('csr'),
        util.get_next_id(jsonloader.conf.ra_options["certdb_file"]),user)

    # Validate CSR
    try:
        new_request.validator_results = validation.validate_csr(
            jsonloader.conf.ra_options["ra_name"],
            auth_result,
            new_request.get_X509csr(),
            pecan_request
        )

    except Exception as e:
        logger.exception("Error running validators: %s", e)
        pecan.abort(500, "Internal Validation Error")

    new_request.Valid = all(list(new_request.validator_results.values()))

    return new_request


def recieve_csr(pecan_request):

    # Check Auth
    auth_result = auth.validate("default",
                                "myusername",
                                "simplepassword")  # hack

    # Parse and validate CSR
    new_request = _parse_csr(pecan_request, auth_result,
                             pecan_request.POST.get('user'))

    logger.info("Certificate Request validated, result: %s ",
                new_request.toInfoString())

    return_str = "Certificate Request Recieved. ID: %d\n" % new_request.request_id

    # If auto_deny when validation fails is enabled, deny cert
    if ((jsonloader.conf.ra_options["auto_deny_if_validation_fails"] == "True")
            & (new_request.Valid is False)):
        new_request.Denied = True
        return_str += "Certificate Request Denied Automatically\n"

    # If user notification of validation is enabled, add info
    if jsonloader.conf.ra_options["notify_user_validation_result"] == "True":
        return_str += "%s\n" % new_request.toInfoString()
        if new_request.Valid is False:
            return_str += new_request.validationResultToString()

    # write request to 'database'
    with open(jsonloader.conf.ra_options["certdb_file"], 'a') as fout:
        fout.write(new_request.serialize())

    return return_str


def fetch_cert(reqid):
    dbdata = util.load_db(jsonloader.conf.ra_options["certdb_file"])
    try:
        if dbdata[reqid].getStatus() == "Revoked":
            return "Cannot fetch, certificate is revoked"
        elif dbdata[reqid].getStatus() == "Issued":
            return dbdata[reqid].get_cert()
        elif dbdata[reqid].getStatus() == "Pending":
            return "Cannot fetch, certificate is not yet Issued"
        elif dbdata[reqid].getStatus() == "Denied":
            return "Cannot fetch, certificate request is Denied"
        else:
            return "Cannot fetch, Unkown state error"
        util.write_db(dbdata, jsonloader.conf.ra_options["certdb_file"])
        return dbdata[reqid].toInfoString()
    except Exception:
        return "Cannot find reqid %d in cert DB" % reqid
