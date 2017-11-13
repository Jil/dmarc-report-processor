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
from xml.etree import ElementTree as ET
import argparse
import json
import zipfile
import tempfile
import contextlib
import collections


header = (
    "orgName", "email", "extraContactInfo", "dateRangeBegin",
    "dateRangeEnd", "domain", "adkim", "aspf", "policy", "percentage",
    "sourceIP", "messageCount", "disposition", "dkim", "spf",
    "reasonType", "comment", "envelopeTo", "headerFrom", "dkimDomain",
    "dkimResult", "dkimHresult", "spfDomain", "spfResult", "xHostName",
)


ReportMetadata = collections.namedtuple(
    'ReportMetadata', 'org_name email extra_contact_info report_id ' +
    'date_begin date_end')


PolicyPublished = collections.namedtuple(
    'PolicyPublished', 'domain adkim aspf p pct')


Record = collections.namedtuple(
    'Record', 'source_ip count disposition dkim spf type comment ' +
    'envelope_to header_from dkim_domain dkim_result dkim_human_result ' +
    'spf_domain spf_result')


# returns meta fields
def get_meta(filename):
    context = ET.iterparse(filename, events=("start", "end"))
    report_metadata = None
    policy_published = None

    # get the root element
    event, root = next(context)
    for event, elem in context:
        if event == "end" and elem.tag == "report_metadata":
            report_metadata = ReportMetadata(
                elem.findtext("org_name"),
                elem.findtext("email"),
                elem.findtext("extra_contact_info"),
                elem.findtext("report_id"),
                elem.findtext("date_range/begin"),
                elem.findtext("date_range/end"),
            )
        elif event == "end" and elem.tag == "policy_published":
            policy_published = PolicyPublished(
                elem.findtext("domain"),
                elem.findtext("adkim"),
                elem.findtext("aspf"),
                elem.findtext("p"),
                elem.findtext("pct"),
            )

        if report_metadata and policy_published:
            return report_metadata, policy_published

        root.clear()

    return None, None


def iter_records(filename):
    context = ET.iterparse(filename, events=("start", "end"))

    # get the root element
    event, root = next(context)

    for event, elem in context:
        if event == "end" and elem.tag == "record":
            yield Record(
                elem.findtext("row/source_ip"),
                elem.findtext("row/count"),
                elem.findtext("row/policy_evaluated/disposition"),
                elem.findtext("row/policy_evaluated/dkim"),
                elem.findtext("row/policy_evaluated/spf"),
                elem.findtext("row/policy_evaluated/reason/type"),
                elem.findtext("row/policy_evaluated/reason/comment"),
                elem.findtext("identifiers/envelope_to"),
                elem.findtext("identifiers/header_from"),
                elem.findtext("auth_results/dkim/domain"),
                elem.findtext("auth_results/dkim/result"),
                elem.findtext("auth_results/dkim/human_result"),
                elem.findtext("auth_results/spf/domain"),
                elem.findtext("auth_results/spf/result"),
            )
            root.clear()
            continue


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


parser = argparse.ArgumentParser()
# epilog="Example: %(prog)s dmarc-xml-file 1> outfile.log")
parser.add_argument("dmarcfile", help="dmarc file in XML format")
# parser.add_argument('--format', '-f',
#     help="Output format, either 'CSV' or 'json'",
#     default='CSV')


def main():
    args = parser.parse_args()
    with extract_file(args.dmarcfile) as filename:
        cleanup_input(filename)
        report_metadata, policy_published = get_meta(filename)
        if not report_metadata:
            print("Error: No valid 'policy_published' and 'report_metadata' " +
                  "xml tags found; File: " + args.dmarcfile, file=sys.stderr)
            raise SystemExit(1)
        print(report_metadata)
        print(policy_published)
        for record in iter_records(filename):
            print(record)


if __name__ == "__main__":
    main()
