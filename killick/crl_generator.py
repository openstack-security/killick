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

import datetime
import logging

from anchor import jsonloader
from anchor.X509 import certificate as anchor_certificate
from anchor.X509 import utils as anchor_utils
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509

from killick import util

logger = logging.getLogger(__name__)


def generate_crl():
    dbdata = util.load_db(jsonloader.conf.ra_options["certdb_file"])
    crl_builder = x509.CertificateRevocationListBuilder()

    # find revoked certs, create revoked cert objects and
    # add to the crl builder
    for req in sorted(dbdata):
        if dbdata[req] is None:
            continue
        if dbdata[req].getStatus() == "Revoked":
            builder = x509.RevokedCertificateBuilder()
            builder = builder.revocation_date(dbdata[req].revocation_date)
            # todo. dg. check this is getting valid serial numbers
            builder = builder.serial_number(dbdata[req].get_cert_serial())
            revoked_certificate = builder.build(backends.default_backend())
            crl_builder = crl_builder.add_revoked_certificate(
                revoked_certificate)

    # set crl lifetimes #todo. dg. what about clock skew? validfrom date in
    # past?
    crl_builder = crl_builder.last_update(datetime.datetime.utcnow())
    crl_lifetime = datetime.timedelta(
        int(jsonloader.conf.revocation_options["crl_lifetime_days"]), 0, 0)
    crl_builder = crl_builder.next_update(
        datetime.datetime.utcnow() + crl_lifetime)

    # get CA cert
    ca_conf = jsonloader.signing_ca_for_registration_authority(
        jsonloader.conf.ra_options["ra_name"])
    try:
        ca_cert = anchor_certificate.X509Certificate.from_file(ca_conf[
                                                               'cert_path'])
    except Exception as e:
        logger.error("Cannot load the signing CA: %s" % (e,))
        raise

    # set CRL cn (issuer name) to that of the CA certificate
    crl_builder = crl_builder.issuer_name(x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME,
                           ca_cert.get_subject()[0].get_value()),
    ]))

    # get private key
    try:
        private_key = anchor_utils.get_private_key_from_file(ca_conf[
                                                             'key_path'])
    except Exception as e:
        logger.error("Cannot load the signing CA private key: %s" % (e,))
        raise
    # generate crl #todo get hash alg from config?
    crl = crl_builder.sign(private_key, hashes.SHA256(), backends.default_backend())

    return crl.public_bytes(
        serialization.Encoding(jsonloader.conf.revocation_options["crl_format"])
    )
