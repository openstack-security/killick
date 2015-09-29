Killick
=======

Killick is a lightweight PKI utilising anchor validation functionality.

install with:

  python setup.py develop

start with:

  pecan serve config.py


list certificates in database:

  curl -X POST http://0.0.0.0:5000/v1/list
  curl -X POST http://0.0.0.0:5000/v1/list/pending
  curl -X POST http://0.0.0.0:5000/v1/list/denied
  curl -X POST http://0.0.0.0:5000/v1/list/revoked


submit csr:

  curl -X POST -F user="test@user.com" -F 'csr=<anchor-test.example.com.csr' http://0.0.0.0:5/v1/sign

deny/revoke/issue a certificate:

  curl http://0.0.0.0:5000/v1/admin/issue/<cert id>
  curl http://0.0.0.0:5000/v1/admin/deny/10012
  curl http://0.0.0.0:5000/v1/admin/revoke/10012
