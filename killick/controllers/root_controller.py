#
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

import logging

import pecan
from pecan import rest

from killick import admin
from killick import crl_generator
from killick import process_request

# from anchor import auth
# from anchor import certificate_ops
# from anchor import wa_admin
# from anchor import wa_request
# hack
# from anchor import jsonloader


logger = logging.getLogger(__name__)


class RobotsController(rest.RestController):
    """Serves /robots.txt that disallows search bots."""

    @pecan.expose(content_type="text/plain")
    def get(self):
        logger.info("Served robots")
        return "User-agent: *\nDisallow: /\n"


class SignController(rest.RestController):
    """Handles POST requests to /sign."""

    @pecan.expose(content_type="text/plain")
    def post(self):
        return process_request.recieve_csr(pecan.request)


class DenyController(rest.RestController):
    """Serves /admin/deny to manage certificate operations."""
    # hack add error handling
    @pecan.expose(content_type="text/plain")
    def get(self, key):
        return admin.deny(int(key)) + "\n"


class IssueController(rest.RestController):
    """Serves /admin/issue to manage certificate operations."""
    @pecan.expose(content_type="text/plain")
    def get(self, key):
        return admin.issue(int(key)) + "\n"


class RevokeController(rest.RestController):
    """Serves /admin/revoke to manage certificate operations."""
    @pecan.expose(content_type="text/plain")
    def get(self, key):
        return admin.revoke(int(key)) + "\n"


class AdminController(rest.RestController):
    """Serves /admin to manage certificate operations."""
    sign = SignController()
    deny = DenyController()
    issue = IssueController()
    revoke = RevokeController()


class FetchController(rest.RestController):
    """Serves /admin to manage certificate operations."""

    @pecan.expose(content_type="text/plain")
    def get(self, key):
        return process_request.fetch_cert(int(key))


class InfoController(rest.RestController):
    """Serves /info to get information about a certificate request."""

    @pecan.expose(content_type="text/plain")
    def get(self, key):
        return admin.info(int(key))


class ListController(rest.RestController):
    """Serves /admin to manage certificate operations."""

    @pecan.expose(content_type="text/plain")
    def get(self, *key):
        return admin.list(key)


class CrlController(rest.RestController):
    """Serves /crl to return a current crl."""

    @pecan.expose(content_type="text/plain")
    def get(self):
        return crl_generator.generate_crl()


class V1Controller(rest.RestController):
    admin = AdminController()
    fetch = FetchController()
    retrieve = FetchController()
    info = InfoController()
    list = ListController()
    sign = SignController()
    crl = CrlController()


class RootController(object):
    robots = RobotsController()
    v1 = V1Controller()
