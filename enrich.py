import hmac
import sys
import re
import hashlib
import urllib2
import requests
import time
import json
from datetime import datetime
from IPy import IP
from urlparse import urlparse
from config import settings

import pprint

ip_whitelist = settings('enrich')['ip_whitelist'].split(',')
#ip_whitelist = ['8.8.8.8']

class DTSigner(object):
  def __init__(self, api_username, api_key):
      self.api_username = api_username
      self.api_key = api_key

  def timestamp(self):
      return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

  def sign(self, timestamp, uri):
      params = ''.join([self.api_username, timestamp, uri])
      return hmac.new(self.api_key, params, digestmod=hashlib.sha1).hexdigest()

def get_behavior_VT(local_index):
  hash_list = local_index['File']
  print '======> VT Enrichment Begins:'
  target = len(hash_list)
  counter = 0
  for item in hash_list:
    counter = counter+1
    portion = 100* counter / target
    print str(portion) + ' %'
    #print settings('enrich')['vt_api_key']
    params = {"apikey": settings('enrich')['vt_api_key'], 'hash': item}
    url = 'https://www.virustotal.com/vtapi/v2/file/behaviour'

    response = requests.get(url, params=params)
    json_response = response.json()
    #print json_response

    uris = []
    try:
      ips = json_response['network']['hosts']
      ips = [x for x in ips if (IP(x).iptype() == 'PUBLIC')]
      ips = [x for x in ips if (x not in ip_whitelist)]
      for packet in json_response['network']['http']:
        parsed_uri = urlparse(packet['uri'])
        netloc = parsed_uri.netloc
        uris.append(netloc)
    except KeyError:
      ips=[]

    for uri in uris:
      if uri not in local_index['DomainName']:
        local_index['DomainName'][uri] = ['{{no_ref}}']
    #print ip_whitelist
    for ip in ips:
      if ip not in local_index['Address'] and ip not in ip_whitelist:
        local_index['Address'][ip] = ['{{no_ref}}']

    if ips or uris:
      local_index['File'][item].append(ips)
      local_index['File'][item].append(uris)

  #pprint.pprint(local_index)
  return local_index



def get_DT_data(local_index, search_type):

  api_username = settings('enrich')['dt_user']
  api_key = settings('enrich')['dt_api_key']
  #api_key = 'DEADBEEFBABECAFE';
  host = 'api.domaintools.com'
  signer = DTSigner(api_username, api_key)

  if search_type == 'ip2domain':
    api_string = '/host-domains'
    obs_list = local_index['Address']
  elif search_type == 'domain2registration':
    api_string = '/whois'
    obs_list = local_index['DomainName']
  else:
    print 'Incorrect search type.'

  print '======> DT Enrichment Begins: ' + search_type
  target = len(obs_list)
  counter = 0
  for item in obs_list:
    counter = counter+1
    portion = 100* counter / target
    print str(portion) + ' %'

    if item:
      uri = '/v1/' + item + api_string

      timestamp = signer.timestamp()
      signature = signer.sign(timestamp, uri)
      queryURL = 'http://{0}{1}?api_username={2}&signature={3}&timestamp={4}'.format(host, uri, api_username, signature, timestamp)
      response = requests.get(queryURL)
      json_response = response.json()
      #print json_response

      if search_type == 'ip2domain':
        uris = []
        try:
          if json_response['response']['ip_addresses']['domain_names']:
            uris = json_response['response']['ip_addresses']['domain_names']
            local_index['Address'][item].append(uris)
            
        except KeyError:
          pass
        for domain in uris:
          if domain not in local_index['DomainName']:
            local_index['DomainName'][domain] = ['{{no_ref}}']
      #Capability to grab registration details - held out for now...needs some work.
      """
      elif search_type == 'domain2registration':
        try:
          record = json_response['response']['whois']['record']
          if record:
            match = re.findall(r'[\w\.-]+@[\w\.-]+', record)
            match = list(set(match))
            local_index['DomainName'][item].append(match)
        except KeyError:
          pass
      """

  return local_index
