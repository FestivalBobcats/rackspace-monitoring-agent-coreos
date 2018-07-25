#!/usr/bin/env python

from __future__ import print_function

import contextlib
import datetime
import errno
import json
import logging
import os
import re
import sys
import traceback

from keystoneclient import exceptions as k_exc
from keystoneclient.v3 import client as k3_client

METRICS = []

AUTH_DETAILS = {'OS_USERNAME': None,
                'OS_PASSWORD': None,
                'OS_TENANT_NAME': None,
                'OS_AUTH_URL': None,
                'OS_USER_DOMAIN_NAME': None,
                'OS_PROJECT_DOMAIN_NAME': None,
                'OS_PROJECT_NAME': None,
                'OS_IDENTITY_API_VERSION': None,
                'OS_AUTH_VERSION': None,
                'OS_ENDPOINT_TYPE': None,
                'OS_API_INSECURE': True,
                'OS_REGION_NAME': 'RegionOne'}

OPENRC = '/root/openrc'
TOKEN_FILE = '/root/.auth_ref.json'

def status(status, message, force_print=False):
    global STATUS
    if status in ('ok', 'warn', 'err'):
        raise ValueError('The status "%s" is not allowed because it creates a '
                         'metric called legacy_state' % status)
    status_line = 'status %s' % status
    if message is not None:
        status_line = ' '.join((status_line, str(message)))
    status_line = status_line.replace('\n', '\\n')
    STATUS = status_line
    if force_print:
        print(STATUS)


def status_ok(message=None, force_print=False, m_name=None):
    status('okay', message, force_print=force_print)


def status_err(message=None, force_print=False, exception=None, m_name=None):
    if exception:
        # a status message cannot exceed 256 characters
        # 'error ' plus up to 250 from the end of the exception
        message = message[-250:]
    status('error', message, force_print=force_print)
    if exception:
        raise exception
    sys.exit(1)


def metric(name, metric_type, value, unit=None, m_name=None, extra_msg=''):
    if len(METRICS) > 49:
        status_err('Maximum of 50 metrics per check', m_name='maas')

    metric_line = 'metric %s %s %s' % (name, metric_type, value)
    if unit is not None:
        metric_line = ' '.join((metric_line, unit))

    metric_line = metric_line.replace('\n', '\\n')
    METRICS.append(metric_line)

    if extra_msg:
        METRICS.append('metric msg string %s' % extra_msg)


def metric_bool(name, success, m_name=None):
    value = success and 1 or 0
    metric(name, 'uint32', value, m_name=m_name)


@contextlib.contextmanager
def print_output():
    try:
        yield
    except SystemExit as e:
        if STATUS:
            print(STATUS)
        raise
    except Exception as e:
        logging.exception('The plugin %s has failed with an unhandled '
                          'exception', sys.argv[0])
        status_err(traceback.format_exc(), force_print=True, exception=e,
                   m_name='maas')
    else:
        if STATUS:
            print(STATUS)
        for metric in METRICS:
            print(metric)


def get_auth_ref():
    auth_details = get_auth_details()
    auth_ref = get_auth_from_file()
    if auth_ref is None:
        auth_ref = keystone_auth(auth_details)

    if is_token_expired(auth_ref, auth_details):
        auth_ref = keystone_auth(auth_details)

    return auth_ref


def get_auth_from_file():
    try:
        with open(TOKEN_FILE) as token_file:
            auth_ref = json.load(token_file)

        return auth_ref
    except IOError as e:
        if e.errno == errno.ENOENT:
            return None
        status_err(str(e), m_name='maas_keystone')


def get_auth_details(openrc_file=OPENRC):
    auth_details = AUTH_DETAILS
    pattern = re.compile(
        '^(?:export\s)?(?P<key>\w+)(?:\s+)?=(?:\s+)?(?P<value>.*)$'
    )

    try:
        with open(openrc_file) as openrc:
            for line in openrc:
                match = pattern.match(line)
                if match is None:
                    continue
                k = match.group('key')
                v = match.group('value')
                if k in auth_details and auth_details[k] is None:
                    auth_details[k] = v
    except IOError as e:
        if e.errno != errno.ENOENT:
            status_err(str(e), m_name='maas_keystone')
        # no openrc file, so we try the environment
        for key in auth_details.keys():
            if key in os.environ:
                auth_details[key] = os.environ.get(key)

    for key in auth_details.keys():
        if auth_details[key] is None:
            status_err('%s not set' % key, m_name='maas_keystone')

    return auth_details


def keystone_auth(auth_details):
    keystone = None
    # NOTE(cloudnull): The password variable maybe double quoted, to
    #                  fix this we strip away any extra quotes in
    #                  the variable.
    pw = auth_details['OS_PASSWORD'].strip('"').strip("'")
    auth_details['OS_PASSWORD'] = pw
    try:
        if (auth_details['OS_IDENTITY_API_VERSION'] == 3 or
                auth_details['OS_AUTH_URL'].endswith('v3')):
            keystone = k3_client.Client(
                username=auth_details['OS_USERNAME'],
                password=auth_details['OS_PASSWORD'],
                user_domain_name=auth_details.get(
                    'OS_USER_DOMAIN_NAME',
                    'Default'
                ),
                project_domain_name=auth_details.get(
                    'OS_PROJECT_DOMAIN_NAME',
                    'Default'
                ),
                project_name=auth_details.get(
                    'OS_PROJECT_NAME',
                    'admin'
                ),
                auth_url=auth_details['OS_AUTH_URL'],
                region_name=auth_details['OS_REGION_NAME']
            )
        else:
            keystone = k2_client.Client(
                username=auth_details['OS_USERNAME'],
                password=auth_details['OS_PASSWORD'],
                tenant_name=auth_details['OS_TENANT_NAME'],
                auth_url=auth_details['OS_AUTH_URL'],
                region_name=auth_details['OS_REGION_NAME']
            )
    except Exception as e:
        metric_bool('client_success', False, m_name='maas_keystone')
        status_err(str(e), m_name='maas_keystone')
    else:
        if keystone:
            return keystone.auth_ref
        else:
            raise k_exc.AuthorizationFailure()
    finally:
        try:
            if keystone:
                with open(TOKEN_FILE, 'w') as token_file:
                    json.dump(keystone.auth_ref, token_file)
        except IOError:
            # if we can't write the file we go on
            pass


def is_token_expired(token, auth_details):
    for fmt in ('%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S.%fZ'):
        try:
            if auth_details['OS_AUTH_URL'].endswith('v3'):
                expires_at = token.get('expires_at')
            else:
                expires_at = token['token'].get('expires')

            expires = datetime.datetime.strptime(expires_at, fmt)
            break
        except ValueError as e:
            pass
    else:
        raise e
    return datetime.datetime.now() >= expires


def get_endpoint_url_for_service(service_type, auth_ref,
                                 url_type='public', version=None):
    # version = the version identifier on the end of the url. eg:
    # for keystone admin api v3:
    # http://172.29.236.3:35357/v3
    # so you'd pass version='v3'
    service_catalog = get_service_catalog(auth_ref)
    auth_version = auth_ref['version']

    for service in service_catalog:
        if service['type'] == service_type:
            for endpoint in service['endpoints']:
                if endpoint['interface'] == url_type:
                    url = get_url_for_type(endpoint, url_type, auth_version)
                    if url is not None:
                        # If version is not provided or it is provided and the url
                        # ends with it, we want to return it, otherwise we want to
                        # do nothing.
                        if not version or url.endswith(version):
                            return url


def get_service_catalog(auth_ref):
    return auth_ref.get('catalog',
                        # Default back to Keystone v2.0's auth-ref format
                        auth_ref.get('serviceCatalog'))


def get_url_for_type(endpoint, url_type, auth_version):
    # TURTLES-694: in kilo environments, we need to avoid v2.0 URLs, otherwise
    # MaaS will 404 when it tries to check openstack services. in only this
    # circumstance, we suggest a different URL; otherwise, for backward
    # compatibility, we give two different endpoint keys a try
    if auth_version == 'v3' and 'v2.0' in endpoint.get('url', ''):
        return None
    return endpoint.get('url', endpoint.get(url_type + 'URL'))


def get_keystone_client(auth_ref=None, endpoint=None, previous_tries=0):
    if previous_tries > 3:
        return None

    # first try to use auth details from auth_ref so we
    # don't need to auth with keystone every time
    if not auth_ref:
        auth_ref = get_auth_ref()

    auth_version = auth_ref['version']
    if not endpoint:
        endpoint = get_endpoint_url_for_service('identity', auth_ref,
                                                'admin')
    if auth_version == 'v3':
        k_client = k3_client
        if not endpoint.endswith('v3'):
            endpoint = '%s/v3' % endpoint
    else:
        k_client = k2_client
    keystone = k_client.Client(auth_ref=auth_ref,
                               endpoint=endpoint,
                               insecure=AUTH_DETAILS['OS_API_INSECURE'])

    try:
        # This should be a rather light-weight call that validates we're
        # actually connected/authenticated.
        keystone.services.list()
    except (k_exc.AuthorizationFailure, k_exc.Unauthorized):
        # Force an update of auth_ref
        auth_ref = force_reauth()
        keystone = get_keystone_client(auth_ref,
                                       endpoint,
                                       previous_tries + 1)
    except (k_exc.HttpServerError, k_exc.ClientException) as e:
        metric_bool('client_success', False, m_name='maas_keystone')
        status_err(str(e), m_name='maas_keystone')
    except Exception as e:
        metric_bool('client_success', False, m_name='maas_keystone')
        status_err(str(e), m_name='maas_keystone')

    return keystone


def force_reauth():
    auth_details = get_auth_details()
    return keystone_auth(auth_details)
