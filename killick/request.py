from datetime import datetime
import json


class request(object):
    """ Class to hold a CSR and its status """
    def __init__(self, ncsr="", nid=0):

        # CSR Info
        self.request_id = nid
        self.recieved_time = datetime.now()
        self.user = ""

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

    """ Returns a textual description of the current request status """
    def getStatus(self):
        if self.Denied:
            return "Denied"
        elif self.Revoked:
            return "Revoked"
        elif self.Issued:
            return "Issued"
        else:
            return "Pending"

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
        txt += "\"recieved_time\": \"%s\"," % str(self.recieved_time.isoformat())
        txt += "\"user\": \"%s\"," % self.user
        txt += "\"csr\": \"%s\"," % self.csr
        txt += "\"Issued\": %s," % str(self.Issued).lower()
        txt += "\"Revoked\": %s," % str(self.Revoked).lower()
        txt += "\"Denied\": %s," % str(self.Denied).lower()
        txt += "\"Valid\": %s," % str(self.Valid).lower()
        txt += "\"validator_results\": %s" % json.dumps(self.validator_results)
        txt += "}\n"
        return txt

    def fromjson(self, jsonstring):
        self.request_id = jsonstring["request_id"]
        self.recieved_time = datetime.strptime(jsonstring["recieved_time"], "%Y-%m-%dT%H:%M:%S.%f" )
        self.user = jsonstring["user"]
        self.csr = jsonstring["csr"]
        self.Issued = jsonstring["Issued"]
        self.Revoked = jsonstring["Revoked"]
        self.Denied = jsonstring["Denied"]
        self.validator_results = jsonstring["validator_results"]
        self.Valid = jsonstring["Valid"]
