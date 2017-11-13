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
import json
import zipfile
import tempfile
import contextlib


# returns meta fields
def get_meta(context):
    report_meta = None
    feedback_pub = None

    # get the root element
    event, root = next(context)
    for event, elem in context:
        if event == "end" and elem.tag == "report_metadata":
            # process record elements
            org_name = (elem.findtext("org_name", 'NULL')).replace(',', '')
            email = (elem.findtext("email", 'NULL')).replace(',', '')
            extra_contact_info = (elem.findtext("extra_contact_info", 'NULL')).replace(',', '')
            report_id = (elem.findtext("report_id", 'NULL')).replace(',', '')
            date_range_begin = (elem.findtext("date_range/begin", 'NULL')).replace(',', '')
            date_range_end = (elem.findtext("date_range/end", 'NULL')).replace(',', '')
            report_meta = (org_name, email, extra_contact_info,
                           date_range_begin, date_range_end)
        elif event == "end" and elem.tag == "policy_published":
            domain = elem.findtext("domain", 'NULL')
            adkim = elem.findtext("adkim", 'NULL')
            aspf = elem.findtext("aspf", 'NULL')
            p = elem.findtext("p", 'NULL')
            pct = elem.findtext("pct", 'NULL')
            feedback_pub = (domain, adkim, aspf, p, pct)

        if feedback_pub and report_meta:
            meta = report_meta + feedback_pub
            return ';'.join(meta)

        root.clear()


def print_record(context, meta, args):

    # get the root element
    event, root = next(context)

    for event, elem in context:
        if event == "end" and elem.tag == "record":

            elements = dict(meta=meta)

            # process record elements
            # NOTE: This may require additional input validation
            elements['source_ip'] = (elem.findtext("row/source_ip", 'NULL')).replace(',', '')
            elements['count'] = (elem.findtext("row/count", 'NULL')).replace(',', '')
            elements['disposition'] = (elem.findtext("row/policy_evaluated/disposition", 'NULL')).replace(',', '')
            elements['dkim'] = (elem.findtext("row/policy_evaluated/dkim", 'NULL')).replace(',', '')
            elements['spf'] = (elem.findtext("row/policy_evaluated/spf", 'NULL')).replace(',', '')
            elements['reason_type'] = (elem.findtext("row/policy_evaluated/reason/type", 'NULL')).replace(',', '')
            elements['comment'] = (elem.findtext("row/policy_evaluated/reason/comment", 'NULL')).replace(',', '')
            elements['envelope_to'] = (elem.findtext("identifiers/envelope_to", 'NULL')).replace(',', '')
            elements['header_from'] = (elem.findtext("identifiers/header_from", 'NULL')).replace(',', '')
            elements['dkim_domain'] = (elem.findtext("auth_results/dkim/domain", 'NULL')).replace(',', '')
            elements['dkim_result'] = (elem.findtext("auth_results/dkim/result", 'NULL')).replace(',', '')
            elements['dkim_hresult'] = (elem.findtext("auth_results/dkim/human_result", 'NULL')).replace(',', '')
            elements['spf_domain'] = (elem.findtext("auth_results/spf/domain", 'NULL')).replace(',', '')
            elements['spf_result'] = (elem.findtext("auth_results/spf/result", 'NULL')).replace(',', '')

            # If you can identify internal IP
            elements['x_host_name'] = "NULL"
            if args.format == 'CSV':
                print("{meta}, source_ip={source_ip}, count={count}, disposition={disposition}, dkim={dkim}, "
                      "spf={spf}, reason_type={reason_type}, comment={comment}, envelope_to={envelope_to}, "
                      "header_from={header_from}, dkim_domain={dkim_domain}, dkim_result={dkim_result}, "
                      "dkim_hresult={dkim_hresult}, spf_domain={spf_domain}, spf_result={spf_result}, "
                      "x-host_name={x_host_name}".format(**elements))
            elif args.format == 'json':
                print(json.dumps(elements))
            else:
                print(meta + ";" + source_ip + ";" + count + ";" + disposition + ";" + dkim
                      + ";" + spf + ";" + reason_type + ";" + comment + ";" + envelope_to
                      + ";" + header_from + ";" + dkim_domain + ";" + dkim_result
                      + ";" + dkim_hresult + ";" + spf_domain + ";" + spf_result
                      + ";" + x_host_name)

            root.clear()
            continue

    return


def cleanup_input(inputfile):
    with open(inputfile) as fp, open(inputfile + '.tmp', 'x') as fp2:
        for line in fp:
            fp2.write(line.replace('>" <xs', '> <xs'))
    os.rename(inputfile + '.tmp', inputfile)


@contextlib.contextmanager
def extract_file(filename):
    if filename.endswith('.zip'):
        with zipfile.ZipFile(filename) as zf:
            zi, = zf.infolist()
            with tempfile.TemporaryDirectory() as tmpdir:
                yield zf.extract(zi, tmpdir)
    else:
        yield filename


def main():
    options = argparse.ArgumentParser(
        epilog="Example: %(prog)s dmarc-xml-file 1> outfile.log")
    options.add_argument("dmarcfile", help="dmarc file in XML format")
    options.add_argument('--format', '-f',
        help="Output format, either 'CSV' or 'json'",
        default='CSV')

    args = options.parse_args()

    with extract_file(args.dmarcfile) as filename:
        cleanup_input(filename)

        meta_fields = get_meta(etree.iterparse(filename, events=("start", "end"), recover=True))
        if not meta_fields:
            print("Error: No valid 'policy_published' and 'report_metadata' xml tags found; File: " + args.dmarcfile, file=sys.stderr)
            sys.exit(1)

        print("orgName;email;extraContactInfo:dateRangeBegin;dateRangeEnd;domain;adkim;aspf;policy;percentage;sourceIP;messageCount;disposition;dkim;spf;reasonType;comment;envelopeTo;headerFrom;dkimDomain;dkimResult;dkimHresult;spfDomain;spfResult;xHostName")
        print_record(etree.iterparse(filename, events=("start", "end"), recover=True), meta_fields, args)


if __name__ == "__main__":
    main()
