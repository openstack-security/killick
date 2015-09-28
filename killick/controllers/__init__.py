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
import json

import pecan
from pecan import rest

from killick import admin
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
        return process_request.recieve_csr(pecan.request.POST.get('csr'),
                                        pecan.request.POST.get('user'))


class AdminController(rest.RestController):
    """Serves /admin to manage certificate operations"""

    @pecan.expose(content_type="text/plain")
    def post(self):
        return admin.processCommand(pecan.request.POST.get('method'))


class ListController(rest.RestController):
    """Serves /admin to manage certificate operations"""

    @pecan.expose(content_type="text/plain")
    def post(self):
        return admin.list()


class RootController(object):
    robots = RobotsController()
    sign = SignController()
    admin = AdminController()
    list = ListController()
