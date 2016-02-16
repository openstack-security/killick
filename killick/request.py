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

import datetime
import json
import logging

from anchor.X509 import signing_request
from cryptography.hazmat import backends
from cryptography import x509

logger = logging.getLogger(__name__)


class request(object):
    """Class to hold a CSR and its status."""

    def __init__(self, ncsr, nid, nuser):

        # CSR Info
        self.request_id = nid
        self.received_time = datetime.datetime.now()
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

        # revocation fields
        self.revocation_date = None

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
        try:
            return signing_request.X509Csr.from_buffer(self.csr.encode('ascii'))
        except Exception as e:
            logger.exception("Exception while parsing the CSR: %s", e)
            raise e

    def get_cert(self):
        return self.cert

    def get_cert_serial(self):
        if self.cert is not None:
            x509cert = x509.load_pem_x509_certificate(self.get_cert(),
                                                      backends.default_backend())
            return x509cert.serial
        else:
            return None

    def toInfoString(self):
        txt = ""
        txt += "ID: %d" % self.request_id
        txt += ", Received: " + self.received_time.strftime("%d/%m/%Y %H:%M")
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
        separators = (',', ':')
        txt = json.dumps({
            "request_id": self.request_id,
            "recieved_time": str(self.recieved_time.isoformat()),
            "user": self.user,
            "csr": self.csr,
            "cert": self.cert,
            "Issued": self.Issued,
            "Revoked": self.Revoked,
            "Denied": self.Denied,
            "Valid": self.Valid,
            "validator_results": self.validator_results,
            "revocation_date": str(self.revocation_date.isoformat()) if
                                   self.revocation_date else None},
            separators=separators)
        return txt + "\n"


    def fromjson(self, jsonstring):
        self.request_id = jsonstring["request_id"]
        self.received_time = datetime.datetime.strptime(
            jsonstring["received_time"], "%Y-%m-%dT%H:%M:%S.%f")
        self.user = jsonstring["user"]
        self.csr = jsonstring["csr"]
        self.cert = jsonstring["cert"]
        self.Issued = jsonstring["Issued"]
        self.Revoked = jsonstring["Revoked"]
        self.Denied = jsonstring["Denied"]
        self.validator_results = jsonstring["validator_results"]
        self.Valid = jsonstring["Valid"]
        if jsonstring["revocation_date"] is None:
            self.revocation_date = jsonstring["revocation_date"]
        else:
            self.revocation_date = datetime.datetime.strptime(
                jsonstring["revocation_date"], "%Y-%m-%dT%H:%M:%S.%f")
