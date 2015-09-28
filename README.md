Killick
=======

Killick is a lightweight PKI utilising anchor validation functionality.

install with:

python setup.py develop

start with:

pecan serve config.py


list certificates in database:

curl -X POST http://0.0.0.0:5000/list

submit csr:

curl -X POST -F user="test@user.com" -F 'csr=<anchor-test.example.com.csr' http://0.0.0.0:5signs
