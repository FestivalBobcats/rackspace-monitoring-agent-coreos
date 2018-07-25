#!/usr/bin/env python

from maas_common import metric
from maas_common import metric_bool
from maas_common import print_output
from maas_common import status_err
from maas_common import status_ok

import argparse
import requests

def check(args):
    check_name = 'maas_k8s_prometheus_%s' % args.check
    try:
        r = requests.get('%s/api/v1/query' % args.prometheus_endpoint,
                         params={'query': args.query},
                         timeout=5)

        if (r.status_code != 200):
            raise Exception("Prometheus returned status code %s" % str(
                r.status_code))
        res = r.json()

        if res['status'] != 'success':
            raise Exception("Prometheus returned status %s" % str(
                res['status']))

        value = 0
        targets = []
        if 'data' in res:
            res = res['data']
            if 'result' in res:
                res = res['result']

                for item in res:
                    # NOTE the actual value isn't what we're after -- all
                    # queries are simply counting the results.
                    value += 1

                    met = item['metric']

                    if 'nodename' in met:
                        target = met['nodename']
                    elif 'node' in met:
                        target = met['node']
                    elif 'container' in met:
                        target = '%s:%s (%s)' % (met['namespace'], met['pod'], met['container'])
                    else:
                        target = met['instance']

                    targets.append(target)

        metric(args.check, 'double', value, extra_msg=', '.join(targets))

    except (requests.HTTPError, requests.Timeout, requests.ConnectionError):
        metric_bool('client_success', False, m_name=check_name)
        # Any other exception presumably isn't an API error

    except Exception as e:
        metric_bool('client_success', False, m_name=check_name)
        status_err(str(e), m_name=check_name)
    else:
        metric_bool('client_success', True, m_name=check_name)

    status_ok(m_name=check_name)

def main(args):
    check(args)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Retrieve values for a check from the Prometheus API')
    parser.add_argument('prometheus_endpoint',
                        help="Prometheus endpoint url")
    parser.add_argument('--query',
                        default=None,
                        type=str,
                        help='the query for Prometheus')
    parser.add_argument('--check',
                        default=None,
                        type=str,
                        help='the name of the check')
    args = parser.parse_args()
    with print_output():
        main(args)
