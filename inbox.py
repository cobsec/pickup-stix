
#
# Copyright 2013, 2014 DTCC
# All Rights Reserved
#
# NOTICE:
#
# All information contained herein is, and remains the property of DTCC and
# its partners, if any.  The intellectual and technical concepts contained
# herein are proprietary to DTCC and its partners and may be covered by U.S.
# and Foreign Patents, patents in process, and are protected by trade secret
# or copyright law.  Dissemination of this information or reproduction of
# this material is strictly forbidden unless prior written permission is
# obtained from DTCC.
#


#
# edge
# pycurl based taxii client
# with examples
#
# default content_binding is stix xml 1.1.1
#     ( see {{content_binding}} )
#
# python2.7 TAXIIExample.py discovery
# python2.7 TAXIIExample.py feedinfo
# python2.7 TAXIIExample.py poll [feed_id]
# python2.7 TAXIIExample.py inbox [file.xml]
#
#
# win32 prerequisites:
#     python-2.7.5.msi
#     lxml-3.2.3.win32-py2.7.exe
#         as-of 20131004: https://pypi.python.org/pypi/lxml/3.2.3#downloads
#	  pycurl-7.19.0.1.win32-py2.7.exe
#         as-of 20131004: http://www.lfd.uci.edu/~gohlke/pythonlibs/
#


import pycurl
import random
import lxml.etree
import xml.etree.ElementTree as ET
import HTMLParser
import StringIO

from xml.parsers.expat import ExpatError

from config import settings

def inbox(stix_package):
    taxii_url = settings('inbox')['taxii_server']
    username = settings('inbox')['taxii_user']
    password = settings('inbox')['taxii_pass']
    user_pwd = username + ":" + password

    xmlstart = """<?xml version="1.0" encoding="UTF-8" ?>"""
    boilerplate = """xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xsi:schemaLocation="http://taxii.mitre.org/messages/taxii_xml_binding-1.1 http://taxii.mitre.org/messages/taxii_xml_binding-1.1" """
    message_id = str(random.randint(345271,9999999999))

    xml_inbox = xmlstart + """
<taxii_11:Inbox_Message {{boilerplate}} message_id="{{message_id}}">
    <taxii_11:Content_Block>
        <taxii_11:Content_Binding binding_id="{{content_binding}}" />
        <taxii_11:Content>
        {{content_data}}
        </taxii_11:Content>
    </taxii_11:Content_Block>
</taxii_11:Inbox_Message>"""

    xml = xml_inbox.replace('{{boilerplate}}',boilerplate) \
                   .replace('{{message_id}}',message_id) \
                   .replace('{{content_binding}}','urn:stix.mitre.org:xml:1.1.1') \
                   .replace('{{content_data}}',stix_package.to_xml())
    #print xml
    headers = [
        "Content-Type: application/xml",
        "Content-Length: " + str(len(xml)),
        "User-Agent: TAXII Client Application",
        "Accept: application/xml",
        "X-TAXII-Accept: urn:taxii.mitre.org:message:xml:1.1",
        "X-TAXII-Content-Type: urn:taxii.mitre.org:message:xml:1.1",
        "X-TAXII-Protocol: urn:taxii.mitre.org:protocol:https:1.0",
    ]

    buf = StringIO.StringIO()

    conn = pycurl.Curl()
    conn.setopt(pycurl.URL, taxii_url)
    conn.setopt(pycurl.USERPWD, user_pwd)
    conn.setopt(pycurl.HTTPHEADER, headers)
    conn.setopt(pycurl.POST, 1)
    conn.setopt(pycurl.TIMEOUT, 999999)
    conn.setopt(pycurl.WRITEFUNCTION, buf.write)
    conn.setopt(pycurl.POSTFIELDS, xml)
    conn.perform()

    hp = HTMLParser.HTMLParser()
    result = hp.unescape(buf.getvalue()).encode('ascii', 'ignore')
    print result
    root = ET.fromstring(result)
    status = root.attrib['status_type']

    return status
