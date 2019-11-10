import argparse
import json
import os

import pefile
from time import time
from os.path import isfile
from itertools import chain
from checkers import YaraChecker, PeidChecker, MLChecker, HashChecker

#### CONFIGURATION ###
verbose = True  # print output on every file analyzed
step = 500  # every how many files to dump results


def list_files(file_arguments):
    for f in file_arguments:
        if os.path.isdir(f):
            for filename in os.listdir(f):
                file_path = os.path.join(f, filename)
                if os.path.isfile(file_path):
                    yield file_path
        elif os.path.isfile(f):
            yield f
        else:
            print "Error:", f, "is not a dir nor a file"


def list_lines(file_path):
    if os.path.isfile(file_path):
        with open(file_path) as file:
            file_content = file.read().splitlines()
            for line in file_content:
                yield line


def write_results(outfile, i, all_matches):
    if i <= 0:
        print "Writing to disk final results..."
    else:
        print 'Writing to disk results of analyzing', i, 'files...'
        outfile = outfile + '_' + str(i)
    with open(outfile, 'w') as j_file:
        json.dump(all_matches, j_file, indent=2)
        print 'Wrote', j_file.name


def add_to_signatures(sigs, rule, checker):
    if not isfile(rule):
        print rule, "not found"
        return
    if checker.isValid:
        try:
            print 'Adding', rule, 'as a', checker.name, '...'
            sigs.append(checker)
            return
        except AttributeError as e:
            print 'Ignoring', rule, 'because of AttributeError: {0}'.format(e.message)
            return
    else:
        print 'WARNING:', rule, 'is not a valid', checker.name, 'and will be ignored.'
        print '-' * 50
        return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Welcome to the PEPAC, the PE PAcker Classifier. This is version 1.2.1."
                    "This is experimental software, given with no guarantees at all to the extent of applicable law.")
    parser.add_argument("-y", "--add-yara-rule", action="append", help="Add the yara rules from the designated file as "
                                                                       "a new set of rules/signature.")
    parser.add_argument("-p", "--add-peid-signature", action="append", help="Add the peid signature from the designated"
                                                                            "file as new set of rules/signatures.")
    parser.add_argument("-l", "--add-hash-list", action="append", help="Add a list of file hashes and classifications")
    parser.add_argument("-c", "--add-classifier", action="append", help="Add a machine learning classifier")
    parser.add_argument("-o", "--output-file", required=True, help="File for storing the results. Will create 3 "
                                                                   "files starting with the given prefix and "
                                                                   "storing ending with packed, unpacked and "
                                                                   "unknown, containing the corresponding "
                                                                   "binaries.")
    parser.add_argument("-q", "--quiet", action="store_false", dest="verbose", default=True,
                        help="Don't print output for each analyzed file")
    parser.add_argument("-s", "--step", metavar='step', type=int, default=500,
                        help="Every how many steps to dump partial results")
    parser.add_argument("-i", "--input-file", action='append', help="Text file containing a list of files to analyze"
                                                                    " (one per row).")
    parser.add_argument("file_or_directory", nargs="*", help="Files or directory containing binary files to scan.")

    args = parser.parse_args()

    yara_rules = args.add_yara_rule
    peid_sigs = args.add_peid_signature
    hash_lists = args.add_hash_list
    classifiers = args.add_classifier

    if not yara_rules and not peid_sigs and not hash_lists and not classifiers:
        print("ERROR: Need at least one signature/rule/hash file/ML classifier.")
        exit(1)

    signatures = []
    if yara_rules:
        for rule in yara_rules:
            add_to_signatures(signatures, rule, YaraChecker(rule))
    if peid_sigs:
        for sig in peid_sigs:
            add_to_signatures(signatures, sig, PeidChecker(sig))
    if hash_lists:
        for list in hash_lists:
            add_to_signatures(signatures, list, HashChecker(list))
    if classifiers:
        for clf in classifiers:
            add_to_signatures(signatures, clf, MLChecker(clf))

    if not signatures:
        print("ERROR: Need at least one valid signature/rule/hash file/ML classifier.")
        exit(1)

    all_matches = {}

    input_generator = None
    if args.input_file:
        print 'Loading file list from input files', args.input_file
        for ifile_path in args.input_file:
            print 'Loading', ifile_path, "..."
            if not isfile(ifile_path):
                print ifile_path, 'not found, skipping it'
                continue
            if input_generator is None:
                input_generator = list_lines(ifile_path)
            else:
                input_generator = chain(input_generator, list_lines(ifile_path))

    count = 0
    for f in chain(input_generator, list_files(args.file_or_directory)):
        count = count + 1
        if verbose:
            print '-----------------------\n', count, "Scanning", f
        if not isfile(f):
            if verbose:
                print 'File does not exist, skipping it'
            continue
        matched_items = {}
        if args.add_peid_signature:
            try:
                pe = pefile.PE(f)

            except pefile.PEFormatError:
                all_matches[f] = 'PE load error'
                continue
        for s in signatures:
            if s.need_mapped_pe:
                try:
                    to_check = pe
                except NameError:
                    all_matches[f] = 'PE name error'

            else:
                to_check = f
            start_time = time()
            matches = s.check(to_check)
            class_time = time() - start_time
            toprint = ""
            tosave = []
            if isinstance(s, MLChecker):
                toprint = '\n'
                cleaned_matches = sorted(matches[0], reverse=True)
                for Class_rank in cleaned_matches:
                    if Class_rank[0] >= 0.001:
                        toprint += format(Class_rank[0] * 100, '.1f') + '% : ' + Class_rank[1] + '\n'
                        tosave.append({"family": Class_rank[1], "probability": format(Class_rank[0] * 100, '.1f')})

            else:
                toprint = matches
                tosave = matches
            if verbose:
                print s.file, '(in ' + format(class_time, '.9f') + ' s):', toprint
            matched_items[s.file] = tosave
        all_matches[f] = matched_items

        if count % step == 0:
            write_results(args.output_file, count, all_matches)

    write_results(args.output_file, 0, all_matches)
