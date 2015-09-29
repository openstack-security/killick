from datetime import datetime
import json
import logging

from anchor.X509 import signing_request

logger = logging.getLogger(__name__)


class request(object):
    """Class to hold a CSR and its status."""

    def __init__(self, ncsr, nid, nuser):

        # CSR Info
        self.request_id = nid
        self.recieved_time = datetime.now()
        self.user = nuser

        # CSR and Cert
        self.csr = ncsr
        self.cert = None

        # Status flags
        # requests can be Issued and Revoked, but not Issued and Denied or
        # Denied and Revoked. If no flags are set, request is pending
        self.Issued = False
        self.Revoked = False
        self.Denied = False

        # Validation results
        self.validator_results = None
        self.Valid = False

    """Returns a textual description of the current request status."""

    def getStatus(self):
        if self.Denied:
            return "Denied"
        elif self.Revoked:
            return "Revoked"
        elif self.Issued:
            return "Issued"
        else:
            return "Pending"

    """Returns a X509csr object containing the CSR for this request."""

    def get_X509csr(self):

        # add newlines after the --begin-- and --end-- to make
        # X509.signing_request.from_open_file work
        csr_string = self.csr[:35] + "\n"
        csr_string += self.csr[35:(len(self.csr) - 33)] + "\n"
        csr_string += self.csr[(len(self.csr) - 33):]
        try:
            return signing_request.X509Csr.from_buffer(unicode(csr_string))
        except Exception as e:
            logger.exception("Exception while parsing the CSR: %s", e)
            raise e

    def get_cert(self):
        newcert = self.cert[:27] + "\n"
        cert_tail = self.cert[(len(self.cert) - 25):] + "\n"
        body = self.cert[27:(len(self.cert) - 25)]
        newcert += '\n'.join([body[i:i + 64] for i in range(0, len(body), 64)])
        newcert += "\n" + cert_tail
        return newcert

    def toInfoString(self):
        txt = ""
        txt += "ID: %d" % self.request_id
        txt += ", Recieved: " + self.recieved_time.strftime("%d/%m/%Y %H:%M")
        txt += ", Status: " + self.getStatus()
        if self.Valid & (self.validator_results is not None):
            txt += ", Ran %d validators: Success" % len(self.validator_results)
        elif self.validator_results:
            txt += ", Ran %d validators: Failure" % len(self.validator_results)
        else:
            txt += ", Ran 0 validators"
        return txt

    def validationResultToString(self):
        txt = "Validation Results:\n"
        for validator in self.validator_results.keys():
            if self.validator_results[validator]:
                txt += " - %s: Pass\n" % validator
            else:
                txt += " - %s: Fail\n" % validator
        return txt

    def serialize(self):
        txt = "{"
        txt += "\"request_id\": %d," % self.request_id
        txt += "\"recieved_time\": \"%s\"," % str(
            self.recieved_time.isoformat())
        txt += "\"user\": \"%s\"," % self.user
        txt += "\"csr\": \"%s\"," % self.csr
        txt += "\"cert\": \"%s\"," % self.cert
        txt += "\"Issued\": %s," % str(self.Issued).lower()
        txt += "\"Revoked\": %s," % str(self.Revoked).lower()
        txt += "\"Denied\": %s," % str(self.Denied).lower()
        txt += "\"Valid\": %s," % str(self.Valid).lower()
        txt += "\"validator_results\": %s" % json.dumps(self.validator_results)
        txt += "}\n"
        return txt

    def fromjson(self, jsonstring):
        self.request_id = jsonstring["request_id"]
        self.recieved_time = datetime.strptime(
            jsonstring["recieved_time"], "%Y-%m-%dT%H:%M:%S.%f")
        self.user = jsonstring["user"]
        self.csr = jsonstring["csr"]
        self.cert = jsonstring["cert"]
        self.Issued = jsonstring["Issued"]
        self.Revoked = jsonstring["Revoked"]
        self.Denied = jsonstring["Denied"]
        self.validator_results = jsonstring["validator_results"]
        self.Valid = jsonstring["Valid"]
