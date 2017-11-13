#!/usr/bin/python
#
# Copyright (c) 2014, Yahoo! Inc.
# Copyrights licensed under the New BSD License. See the
# accompanying LICENSE.txt file for terms.
#
# Author Binu P. Ramakrishnan
# Created 09/12/2014
#
# Program that accepts a (LARGE) xml file and convert it to 
# easy-to-process comma separated key=value pair format 
# (line oriented splunk friendly record format)
#
# Usage: dmarc-parser.py <input xml file> 1> outfile
# Returns 0 for success and 1 for errors. 
# Error messages are directed to stderr
#
import sys
import os
from lxml import etree
import argparse
import socket
import fileinput

# returns meta fields
def get_meta(context):
  report_meta = ""
  feedback_pub = ""

  pp = 0
  rm = 0  

  # get the root element
  event, root = context.next()
  for event, elem in context:
    if event == "end" and elem.tag == "report_metadata":
      # process record elements
      org_name = (elem.findtext("org_name", 'NULL')).translate(None, ',')
      email = (elem.findtext("email", 'NULL')).translate(None, ',')
      extra_contact_info = (elem.findtext("extra_contact_info", 'NULL')).translate(None, ',')
      report_id = (elem.findtext("report_id", 'NULL')).translate(None, ',')
      date_range_begin = (elem.findtext("date_range/begin", 'NULL')).translate(None, ',')
      date_range_end = (elem.findtext("date_range/end", 'NULL')).translate(None, ',')

      report_meta =  org_name + ";" + email + ";" + extra_contact_info \
            + ";" + date_range_begin + ";" + date_range_end
      rm = 1
      root.clear();
      continue

    if event == "end" and elem.tag == "policy_published":
      domain = elem.findtext("domain", 'NULL')
      adkim = elem.findtext("adkim", 'NULL')
      aspf = elem.findtext("aspf", 'NULL')
      p = elem.findtext("p", 'NULL')
      pct = elem.findtext("pct", 'NULL')

      feedback_pub = ";" + domain + ";" + adkim + ";" + aspf + ";" + p + ";" + pct
      pp = 1
      root.clear();
      continue      

    if pp == 1 and rm == 1:
      meta = report_meta + feedback_pub
      #print meta
      return meta
  
  return

def print_record(context, meta, args):

  # get the root element
  event, root = context.next();

  for event, elem in context:
    if event == "end" and elem.tag == "record":

      # process record elements
      # NOTE: This may require additional input validation
      source_ip = (elem.findtext("row/source_ip", 'NULL')).translate(None, ',')
      count = (elem.findtext("row/count", 'NULL')).translate(None, ',')
      disposition = (elem.findtext("row/policy_evaluated/disposition", 'NULL')).translate(None, ',')
      dkim = (elem.findtext("row/policy_evaluated/dkim", 'NULL')).translate(None, ',')
      spf = (elem.findtext("row/policy_evaluated/spf", 'NULL')).translate(None, ',')
      reason_type = (elem.findtext("row/policy_evaluated/reason/type", 'NULL')).translate(None, ',')
      comment = (elem.findtext("row/policy_evaluated/reason/comment", 'NULL')).translate(None, ',')
      envelope_to = (elem.findtext("identifiers/envelope_to", 'NULL')).translate(None, ',')
      header_from = (elem.findtext("identifiers/header_from", 'NULL')).translate(None, ',')
      dkim_domain = (elem.findtext("auth_results/dkim/domain", 'NULL')).translate(None, ',')
      dkim_result = (elem.findtext("auth_results/dkim/result", 'NULL')).translate(None, ',')
      dkim_hresult = (elem.findtext("auth_results/dkim/human_result", 'NULL')).translate(None, ',')
      spf_domain = (elem.findtext("auth_results/spf/domain", 'NULL')).translate(None, ',')
      spf_result = (elem.findtext("auth_results/spf/result", 'NULL')).translate(None, ',')

      # If you can identify internal IP
      x_host_name = "NULL"
      #try:
      #  if IS_INTERNAL_IP(source_ip):
      #    x_host_name = socket.getfqdn(source_ip)
      #except: 
      #  x_host_name = "NULL"
			
      print meta + ";" + source_ip + ";" + count + ";" + disposition + ";" + dkim \
            + ";" + spf + ";" + reason_type + ";" + comment + ";" + envelope_to \
            + ";" + header_from + ";" + dkim_domain + ";" + dkim_result \
            + ";" + dkim_hresult + ";" + spf_domain + ";" + spf_result  \
            + ";" + x_host_name

      root.clear();
      continue

  return;

def cleanup_input(inputfile):
  for line in fileinput.input(inputfile, inplace = 1): 
    print line.replace('>" <xs', '> <xs')
  return;


def main():
  global args
  options = argparse.ArgumentParser(epilog="Example: \
%(prog)s dmarc-xml-file 1> outfile.log")
  options.add_argument("dmarcfile", help="dmarc file in XML format")
  args = options.parse_args()

  cleanup_input(args.dmarcfile);

  # get an iterable and turn it into an iterator
  meta_fields = get_meta(iter(etree.iterparse(args.dmarcfile, events=("start", "end"), recover=True)));
  if not meta_fields:
    print >> sys.stderr, "Error: No valid 'policy_published' and 'report_metadata' xml tags found; File: " + args.dmarcfile 
    sys.exit(1)

  print "orgName;email;extraContactInfo:dateRangeBegin;dateRangeEnd;domain;adkim;aspf;policy;percentage;sourceIP;messageCount;disposition;dkim;spf;reasonType;comment;envelopeTo;headerFrom;dkimDomain;dkimResult;dkimHresult;spfDomain;spfResult;xHostName"
  print_record(iter(etree.iterparse(args.dmarcfile, events=("start", "end"), recover=True)), meta_fields, args)
  os.remove(args.dmarcfile)

if __name__ == "__main__":
  main()

