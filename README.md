Killick
=======

Killick is a lightweight PKI utilising anchor validation functionality.

Install
-------

install with:

    virtualenv .killick-venv (optional)
    . .killick-venv/bin/activate  (optional)
    pip install pyasn1
    pip install cryptography
    python setup.py develop
    git clone git://git.openstack.org/openstack/anchor
    pip install anchor/


Launch
------

start with:

    pecan serve config.py


list certificates in database:

    curl http://0.0.0.0:5017/v1/list
    curl http://0.0.0.0:5017/v1/list/pending
    curl http://0.0.0.0:5017/v1/list/denied
    curl http://0.0.0.0:5017/v1/list/revoked


submit csr:

    curl -X POST -F user="test@user.com" -F 'csr=<anchor-test.example.com.csr' http://0.0.0.0:5017/v1/sign

deny/revoke/issue a certificate:

    curl http://0.0.0.0:5017/v1/admin/issue/<cert id>
    curl http://0.0.0.0:5017/v1/admin/deny/10012
    curl http://0.0.0.0:5017/v1/admin/revoke/10012

fetch/retrieve a certificate:

    curl http://0.0.0.0:5017/v1/fetch/<cert id>
    curl http://0.0.0.0:5017/v1/retrieve/<cert id>

fetch certificate revocation list (crl):

    curl http://0.0.0.0:5017/v1/crl


Todo
----

- Add 'view expired'
- add 'issued date'
- add 'expirey date'
