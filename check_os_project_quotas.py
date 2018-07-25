#!/usr/bin/env python

from maas_common import get_auth_ref
from maas_common import get_endpoint_url_for_service
from maas_common import get_keystone_client
from maas_common import metric
from maas_common import metric_bool
from maas_common import print_output
from maas_common import status_err
from maas_common import status_ok

import argparse
import requests




# TODO
# TODO
# TODO
alert_usage_threshold = 0
endpoint_type = 'public'





def get(session, url, params={}, headers={}):
    r = session.get(url, timeout=5, params=params, headers=headers)

    if (r.status_code != 200):
        raise Exception("%s returned status code %d" % (url, r.status_code))

    return r


def quota_usage(usage, limit):
    return 0 if limit == 0 else max(0, usage / float(limit) * 100)


def quota_metric(name, usage, limit):
    metric(name,
           'double',
           '%.3f' % quota_usage(usage, limit),
           '%',
           m_name='maas_quotas')


def nested_quota_metric(name, nested_item_name, items, limit, usage_fn,
                        name_keys=['name']):
    quota_usage_key = '%s_quota_usage' % nested_item_name

    for item in items:
        item['name_for_quota'] = '/'.join(map(lambda k: item[k], name_keys))
        item[quota_usage_key] = quota_usage(usage_fn(item), limit)

    items_exceeding_quota = [
        '%s: %.3f%%' % (item['name_for_quota'], item[quota_usage_key])
        for item in items
        if item[quota_usage_key] >= alert_usage_threshold]

    metric(name,
           'string',
           ', '.join(items_exceeding_quota),
           m_name='maas_quotas')


def check(auth_ref, args):
    endpoint = get_endpoint_url_for_service('identity', auth_ref, 'public')
    keystone = get_keystone_client(auth_ref, endpoint)
    auth_token = keystone.auth_token

    print(auth_ref)

    # tenant_id = args.tenant_id

    s = requests.Session()
    s.verify = False
    s.headers.update({'Content-type': 'application/json',
                      'x-auth-token': auth_token})

    tenant_params = {'project_id': tenant_id}


    compute_endpoint = get_endpoint_url_for_service(
        'compute', auth_ref, endpoint_type)

    volume_endpoint = get_endpoint_url_for_service(
        'volumev2', auth_ref, endpoint_type)

    network_endpoint = get_endpoint_url_for_service(
        'network', auth_ref, endpoint_type)

    dns_endpoint = get_endpoint_url_for_service(
        'dns', auth_ref, endpoint_type)

    object_store_endpoint = get_endpoint_url_for_service(
        'object-store', auth_ref, endpoint_type)


    try:
        compute_limits = get(s,
            '%s/limits' % compute_endpoint,
            tenant_params).json()['limits']['absolute']

        server_groups = get(s,
            '%s/os-server-groups' % compute_endpoint,
            tenant_params).json()['server_groups']

        volume_limits = get(s,
            '%s/limits' % volume_endpoint,
            tenant_params).json()['limits']['absolute']

        network_quotas = get(s,
            '%s/v2.0/quotas/%s' % (network_endpoint, tenant_id),
            tenant_params).json()['quota']

        network_count = len(get(s,
            '%s/v2.0/networks' % network_endpoint,
            tenant_params).json()['networks'])

        port_count = len(get(s,
            '%s/v2.0/ports' % network_endpoint,
            tenant_params).json()['ports'])

        rbac_policy_count = len(get(s,
            '%s/v2.0/rbac-policies' % network_endpoint,
            tenant_params).json()['rbac_policies'])

        router_count = len(get(s,
            '%s/v2.0/routers' % network_endpoint,
            tenant_params).json()['routers'])

        security_group_rule_count = len(get(s,
            '%s/v2.0/security-group-rules' % network_endpoint,
            tenant_params).json()['security_group_rules'])

        subnet_count = len(get(s,
            '%s/v2.0/subnets' % network_endpoint,
            tenant_params).json()['subnets'])

        subnet_pool_count = len(get(s,
            '%s/v2.0/subnetpools' % network_endpoint,
            tenant_params).json()['subnetpools'])

        dns_quotas = get(s,
            '%s/v2/quotas/%s' % (dns_endpoint, tenant_id),
            headers={'x-auth-all-projects': 'True'}).json()

        dns_zones = get(s,
            '%s/v2/zones' % dns_endpoint,
            headers={'x-auth-sudo-project-id': tenant_id}).json()['zones']

        dns_recordsets = get(s,
            '%s/v2/recordsets' % dns_endpoint,
            headers={'x-auth-sudo-project-id': tenant_id}).json()['recordsets']

        for dz in dns_zones:
            recordsets = [
                rs for rs in
                project_quota_usage[project.name]['dns_zones_recordsets']
                if rs['zone_name'] == dz['name']
            ]
            dz['recordsets_usage'] = len(recordsets)
            dz['records_usage'] = sum([len(rs['records']) for rs in recordsets])

        swift_containers_resp = get(s,
            '%s?format=json' % object_store_endpoint, tenant_params)

        swift_stats = swift_containers_resp.headers
        swift_containers = swift_containers_resp.json()

        swift_account_bytes_quota = int(swift_stats.get(
            'X-Account-Meta-Quota-Bytes', -1))
        swift_container_bytes_quota = int(swift_stats.get(
            'X-Container-Meta-Quota-Bytes', -1))
        swift_container_objects_quota = int(swift_stats.get(
            'X-Container-Meta-Quota-Count', -1))

    except (requests.HTTPError, requests.Timeout, requests.ConnectionError):
        metric_bool('client_success', False, m_name='maas_quotas')
    # Any other exception presumably isn't an API error
    except Exception as e:
        metric_bool('client_success', False, m_name='maas_quotas')
        status_err(str(e), m_name='maas_quotas')
    else:
        metric_bool('client_success', True, m_name='maas_quotas')

    status_ok(m_name='maas_quotas')


    # (Compute) Cores
    quota_metric('os_cores_quota_usage',
                 compute_limits['totalCoresUsed'],
                 compute_limits['maxTotalCores'])

    # (Compute) Instances
    quota_metric('os_instances_quota_usage',
                 compute_limits['totalInstancesUsed'],
                 compute_limits['maxTotalInstances'])

    # (Compute) RAM
    quota_metric('os_ram_quota_usage',
                 compute_limits['totalRAMUsed'],
                 compute_limits['maxTotalRAMSize'])

    # (Compute) Server groups
    quota_metric('os_server_groups_quota_usage',
                 compute_limits['totalServerGroupsUsed'],
                 compute_limits['maxServerGroups'])

    # (Compute) Server group members
    nested_quota_metric(
        'os_server_groups_exceeding_members_quota_threshold',
        'members',
        server_groups,
        compute_limits['maxServerGroupMembers'],
        lambda sg: len(sg['members']))

    # (Volume) Backups
    quota_metric('os_backups_quota_usage',
                 volume_limits['totalBackupsUsed'],
                 volume_limits['maxTotalBackups'])

    # (Volume) Backup gigabytes
    quota_metric('os_backups_quota_usage',
                 volume_limits['totalBackupGigabytesUsed'],
                 volume_limits['maxTotalBackupGigabytes'])

    # (Volume) Gigabytes
    quota_metric('os_volume_gb_quota_usage',
                 volume_limits['totalGigabytesUsed'],
                 volume_limits['maxTotalVolumeGigabytes'])

    # (Volume) Snapshots
    quota_metric('os_snapshots_quota_usage',
                 volume_limits['totalSnapshotsUsed'],
                 volume_limits['maxTotalSnapshots'])

    # (Volume) Volumes
    quota_metric('os_volumes_quota_usage',
                 volume_limits['totalVolumesUsed'],
                 volume_limits['maxTotalVolumes'])

    # (Network) Floating IPs
    quota_metric('os_floating_ips_quota_usage',
                 compute_limits['totalFloatingIpsUsed'],
                 compute_limits['maxTotalFloatingIps'])

    # (Network) Networks
    quota_metric('os_networks_quota_usage',
                 network_count,
                 network_quotas['network'])

    # (Network) Ports
    quota_metric('os_ports_quota_usage',
                 port_count,
                 network_quotas['port'])

    # (Network) RBAC policies
    quota_metric('os_rbac_policies_quota_usage',
                 rbac_policy_count,
                 network_quotas['rbac_policy'])

    # (Network) Routers
    quota_metric('os_routers_quota_usage',
                 router_count,
                 network_quotas['router'])

    # (Network) Security groups
    quota_metric('os_security_groups_quota_usage',
                 compute_limits['totalSecurityGroupsUsed'],
                 compute_limits['maxSecurityGroups'])

    # (Network) Security group rules
    quota_metric('os_security_group_rules_quota_usage',
                 security_group_rule_count,
                 network_quotas['security_group_rule'])

    # (Network) Subnets
    quota_metric('os_subnets_quota_usage',
                 subnet_count,
                 network_quotas['subnet'])

    # (Network) Subnet pools
    quota_metric('os_subnet_pools_quota_usage',
                 subnet_pool_count,
                 network_quotas['subnetpool'])

    # (DNS) Zones
    quota_metric('os_dns_zones_quota_usage',
                 len(dns_zones),
                 dns_quotas['zones'])

    # (DNS) Zone recordsets
    nested_quota_metric(
        'os_dns_zones_exceeding_recordsets_quota_threshold',
        'recordsets',
        dns_zones,
        dns_quotas['zone_recordsets'],
        lambda dz: dz['recordsets_usage'])

    # (DNS) Zone records
    nested_quota_metric(
        'os_dns_zones_exceeding_records_quota_threshold',
        'records',
        dns_zones,
        dns_quotas['zone_records'],
        lambda dz: dz['records_usage'])

    # (DNS) Recordset records
    nested_quota_metric(
        'os_dns_zone_recordsets_exceeding_records_quota_threshold',
        'records',
        dns_recordsets,
        dns_quotas['recordset_records'],
        lambda rs: len(rs['records']),
        name_keys=('zone_name', 'name'))

    # (Object storage) Bytes
    quota_metric('os_object_store_account_bytes_quota_usage',
                 int(swift_stats.get('X-Account-Bytes-Used')),
                 swift_account_bytes_quota)

    # (Object storage) Container objects
    nested_quota_metric(
        'os_object_store_containers_exceeding_objects_quota_threshold',
        'objects',
        swift_containers,
        swift_container_objects_quota,
        lambda container: container['count'])

    # (Object storage) Container bytes
    nested_quota_metric(
        'os_object_store_containers_exceeding_bytes_quota_threshold',
        'bytes',
        swift_containers,
        swift_container_bytes_quota,
        lambda container: container['bytes'])


def main(args):
    auth_ref = get_auth_ref()
    check(auth_ref, args)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Check quotas for the OpenStack project')
    # parser.add_argument('tenant-id',
    #                     help='Check OpenStack project quotas')
    args = parser.parse_args()
    with print_output():
        main(args)
