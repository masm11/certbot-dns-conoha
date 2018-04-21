#!/usr/bin/env python

"""DNS Authenticator for ConoHa."""

import json
import requests
import logging

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for CononHa
    
    This Authenticator uses the ConoHa DNS v1 API to fulfill a dns-01 challenge.
    """
    
    description = 'Obtain certificate using a DNS TXT record (if you are using ConoHa DNS).'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None
    
    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=60)
        add('credentials', help='ConoHa DNS credentials INI file.')
    
    def more_info(self):
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using the ConoHa API.'
    
    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'ConoHa API credentials INI file',
            {
                'endpoint': 'Endpoint of ConoHa Identity API including "/v2.0".',
                'tenant_id': 'Tenant ID.',
                'username': 'Username of ConoHa API user. Neither username in your OS, nor your VPS contract name',
                'password': 'Password of the ConoHa API user',
                'region': 'Such as tyo1',
            })
    
    def _perform(self, domain, validation_name, validation):
        logger.debug('domain=%s, validation_name=%s, validation=%s', domain, validation_name, validation)
        token, dns_v1_url = self.__get_token()
        domain_uuid, domain_host = self.__get_domain_uuid(token, dns_v1_url, validation_name)
        rr_uuid = self.__get_rr_uuid(token, dns_v1_url, domain_uuid, domain_host)
        if rr_uuid:
            rr_uuid = self.__update_rr(token, dns_v1_url, domain_uuid, validation)
        else:
            rr_uuid = self.__insert_rr(token, dns_v1_url, domain_uuid, validation_name, validation)
    
    def _cleanup(self, domain, validation_name, validation):
        logger.debug('domain=%s, validation_name=%s, validation=%s', domain, validation_name, validation)
        token, dns_v1_url = self.__get_token()
        domain_uuid, domain_host = self.__get_domain_uuid(token, dns_v1_url, validation_name)
        rr_uuid = self.__get_rr_uuid(token, dns_v1_url, domain_uuid, validation_name)
        if not rr_uuid:
            raise RuntimeError('No such resource record.')
        self.__delete_rr(token, dns_v1_url, domain_uuid, rr_uuid)
    
    def __get_token(self):
        """Get token and DNS URL."""
        r = requests.post(self.credentials.conf('endpoint') + '/tokens', json={
            'auth': {
                'passwordCredentials': {
                    'username': self.credentials.conf('username'),
                    'password': self.credentials.conf('password'),
                },
                'tenantId': self.credentials.conf('tenant_id'),
            },
        })
        logger.debug('request:')
        logger.debug('%s', r.request.body)
        print(r.status_code)
        if r.status_code != 200:
            logger.debug('%s', r.content)
            logger.debug('%s', r.json())
            raise RuntimeError('It failed to get token.')
        logger.debug('%s', r.content)
        j = r.json()
        logger.debug('%s', j)
        token = j['access']['token']['id']
        
        # Get DNS URL.
        
        dns_vers_url = None
        for svc in j['access']['serviceCatalog']:
            if svc['type'] == 'dns':
                for ep in svc['endpoints']:
                    if ep['region'] == self.credentials.conf('region'):
                        dns_vers_url = ep['publicURL']
        if not dns_vers_url:
            raise RuntimeError('It failed to get DNSv1 URL.')
        
        # Get DNSv1 URL.
        r = requests.get(dns_vers_url, headers={'Accept': 'application/json'})
        print(r.status_code)
        if r.status_code != 300:
            logger.debug('%s', r.content)
            logger.debug('%s', r.json())
            raise RuntimeError('It failed to get DNS URLs.')
        logger.debug('%s', r.content)
        j = r.json()
        logger.debug('%s', j)
        
        url = None
        for val in j['versions']['values']:
            if val['id'] == 'v1':
                url = val['links'][0]['href']
        if not url:
            raise RuntimeError('No DNS v1 URL.')
        return (token, url)
    
    def __get_domain_uuid(self, token, dns_v1_url, domain):
        """Get domain list."""
        if domain[-1] != '.':
            domain = f'{domain}.'
        r = requests.get(dns_v1_url + '/domains', headers={'X-Auth-Token': token, 'Accept': 'application/json'})
        print(r.status_code)
        if r.status_code != 200:
            logger.debug('%s', r.content)
            logger.debug('%s', r.json())
            raise RuntimeError('It failed to get domain list.')
        logger.debug('%s', r.content)
        j = r.json()
        logger.debug('j=%s', j)
        cur_uuid = None
        cur_domlen = 0
        for dm in j['domains']:
            logger.debug('domain name: %s', dm['name'])
            this_name = f".{dm['name']}"
            if domain.endswith(this_name):
                logger.debug('endswith: true.')
                if len(this_name) > cur_domlen:
                    logger.debug('more match.')
                    cur_uuid = dm['id']
                    cur_domlen = len(this_name)
        logger.debug('finally:')
        logger.debug('cur_uuid=%s', cur_uuid)
        logger.debug('cur_domlen=%d', cur_domlen)
        logger.debug('host=%s', domain[:-cur_domlen])
        return (cur_uuid, domain[:-cur_domlen])
    
    def __get_rr_uuid(self, token, dns_v1_url, domain_uuid, name):
        """Get resource record."""
        if name[-1] != '.':
            name = f'{name}.'
        r = requests.get(dns_v1_url + '/domains/' + domain_uuid + '/records', headers={'X-Auth-Token': token, 'Accept': 'application/json'})
        print(r.status_code)
        if r.status_code != 200:
            logger.debug('%s', r.content)
            logger.debug('%s', r.json())
            raise RuntimeError('It failed to get resource record.')
        logger.debug('%s', r.content)
        j = r.json()
        logger.debug('%s', j)
        
        for rr in j['records']:
            if rr['type'] == 'TXT' and rr['name'] == name:
                return rr['id']
        return None
    
    def __update_rr(self, token, dns_v1_url, domain_uuid, rr_uuid, data):
        """Update resource record."""
        # If it exists, then update it.
        r = requests.put(dns_v1_url + '/domains/' + domain_uuid + '/records/' + rr_uuid, headers={
            'X-Auth-Token': token,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }, json={
            'data': data,
            'ttl': 60,
        })
        logger.debug('request:')
        logger.debug('%s', r.request.body)
        print(r.status_code)
        if r.status_code != 200:
            logger.debug('%s', r.content)
            logger.debug('%s', r.json())
            raise RuntimeError('It failed to update resource record.')
        j = r.json()
        return j['id']
    
    def __insert_rr(self, token, dns_v1_url, domain_uuid, name, data):
        # If not exists, then insert one.
        logger.debug('domain_uuid=%s, name=%s', domain_uuid, name) 
        if name[-1] != '.':
            name = f'{name}.'
        r = requests.post(dns_v1_url + '/domains/' + domain_uuid + '/records', headers={
            'X-Auth-Token': token,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }, json={
            'name': name,
            'type': 'TXT',
            'data': data,
            'ttl': 60,
        })
        logger.debug('request:')
        logger.debug('%s', r.request.body)
        
        print(r.status_code)
        if r.status_code != 200:
            logger.debug('%s', r.content)
            logger.debug('%s', r.json())
            raise RuntimeError('It failed to insert resource record.')
        j = r.json()
        return j['id']
    
    def __delete_rr(self, token, dns_v1_url, domain_uuid, rr_uuid):
        """Delete resource record."""
        r = requests.delete(dns_v1_url + '/domains/' + domain_uuid + '/records/' + rr_uuid, headers={
            'X-Auth-Token': token,
            'Accept': 'application/json',
        })
        
        print(r.status_code)
        if r.status_code != 200:
            logger.debug('%s', r.content)
            raise RuntimeError('It failed to delete resource record.')
