#!/usr/bin/env python

import sys
from IPy import IP
from urlparse import urlparse
from pprint import pprint

#===========
# Custom Modules
#===========
from exploit import csv2stix, get_obs_from_stix, index2stix
from inbox import inbox
from enrich import get_behavior_VT, get_DT_data
from deploy import snortify_local
from config import settings

verbose = settings('main')['verbose_mode']
def main():
  args = sys.argv[1:]
  if len(args) == 1:
    stixIngest = csv2stix('stix',args[0])
    print stixIngest.to_xml()

    ingest_status = inbox(stixIngest)
    print 'Initial report ingest status: ' + ingest_status

    orig_index = get_obs_from_stix(stixIngest)
    #pprint(orig_index)

    local_index = orig_index
    local_index = get_behavior_VT(local_index)
    local_index = get_DT_data(local_index, 'ip2domain')
    local_index = get_DT_data(local_index, 'domain2registration')

    new_stix = index2stix(local_index, stixIngest)
    #pprint(local_index)
    print new_stix.to_xml()

    new_ingest_status = inbox(new_stix)
    print 'Enriched report ingest status: ' + new_ingest_status

  else:
    print 'Usage: main.py [inputFile: *.csv]'

if __name__ == '__main__':
                main()
