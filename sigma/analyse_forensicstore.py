# Copyright (c) 2020 Siemens AG
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# Author(s): Jonas Hagg

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from sqlite3 import OperationalError

import forensicstore
from forensicstore_backend import ForensicStoreBackend
from sigma.configuration import SigmaConfiguration
from sigma.parser.collection import SigmaCollectionParser
from sigma.parser.exceptions import SigmaParseError


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def error(msg, *argv):
    logging.info(bcolors.FAIL + msg + bcolors.ENDC, *argv)


def info(msg, *argv):
    logging.info(bcolors.OKGREEN + msg + bcolors.ENDC, *argv)


def warning(msg, *argv):
    logging.warning(bcolors.WARNING + msg + bcolors.ENDC, *argv)


class ErrorHelper:
    def __init__(self, message):
        self.message = message
        self.count = 0
        self.files = []

    def add(self, file):
        self.count += 1
        self.files.append(file)


class Statistics:

    def __init__(self):
        self.missingFieldNames = set()
        self.errors = {}
        self.totalFiles = 0
        self.successFiles = 0

    def error_add(self, val, file):
        val = str(val)
        if val not in self.errors:
            self.errors[val] = ErrorHelper(val)
        self.errors[val].add(file)


class ForensicstoreSigma:

    def __init__(self, url, sigmaconfig):
        if not os.path.exists(sigmaconfig):
            raise FileNotFoundError(sigmaconfig)
        if not os.path.exists(url):
            raise FileNotFoundError(url)

        self.table = "elements"
        self.store = forensicstore.open(url)
        self.config = SigmaConfiguration(open(sigmaconfig))
        self.SQL = ForensicStoreBackend(self.config)

    def __del__(self):
        try:
            self.store.close()
        except Exception as e:
            pass

    def generateSqlQuery(self, sigma_io):

        try:
            # Check if sigma_io can be parsed
            parser = SigmaCollectionParser(sigma_io, self.config, None)
        except Exception as e:
            raise SigmaParseError("Parsing error: {}".format(e))

        # generate sql query
        queries = list(parser.generate(self.SQL))

        # extract parsed rules
        parsed_rules = [parser.parsedyaml for parser in parser.parsers]

        # returns the SQL-Query with the parsed rule
        return list(zip(queries, parsed_rules))

    def handleFile(self, path):
        if type(path) != str or not os.path.exists(path):
            return False

        with open(path) as sigma_io:
            queries = self.generateSqlQuery(sigma_io)
            for query, rule in queries:
                result = self.store.query(query)
                for element in result:
                    dic = {"name": rule["title"],
                           "level": rule["level"],
                           "type": "alert"}
                    dic.update(element)
                    if "System" in dic and "TimeCreated" in dic["System"] and "SystemTime" in dic["System"][
                        "TimeCreated"]:
                        t = datetime.fromtimestamp(int(dic["System"]["TimeCreated"]["SystemTime"]))
                        dic["time"] = t.isoformat()
                    if "agg" not in element:
                        dic["item_ref"] = element["id"]
                    print(json.dumps(dic))
            return True

    def analyseStore(self, path):
        statistics = Statistics()

        for root, _, files in os.walk(path):
            for name in files:
                statistics.totalFiles += 1
                sigmafile = os.path.join(root, name)
                try:
                    if self.handleFile(sigmafile):
                        statistics.successFiles += 1

                except SigmaParseError as e:
                    error("Error in %s: %s", sigmafile, e)
                    statistics.error_add(e, sigmafile)

                except TypeError as e:
                    error("Error in %s: %s", sigmafile, e)
                    statistics.error_add(e, sigmafile)

                except ValueError as e:
                    error("Error in %s: %s", sigmafile, e)
                    statistics.error_add(e, sigmafile)

                except OperationalError as e:
                    statistics.missingFieldNames.add(str(e).split(": ")[1])
                    statistics.error_add(e, sigmafile)
                    warning("Add field_mapping in %s: %s", sigmafile, e)

                except NotImplementedError as e:
                    info("Not implemented %s: %s", sigmafile, e)
                    statistics.error_add(e, sigmafile)

                except Exception as e:
                    error("Unexpected Exeption in {}: {} ({})".format(str(sigmafile), str(e), type(e)))
                    exit(0)

        return statistics


def main():
    header = [
        "name",
        "level",
        "time",
        "System.Computer",
        "System.EventRecordID",
        "System.EventID.Value",
        "System.Level",
        "System.Channel",
        "System.Provider.Name",
    ]
    print(json.dumps({"header": header}))

    parser = argparse.ArgumentParser(description="Process forensic images and extract artifacts")
    parser.add_argument('--debug', dest='debug', action='store_true', default=False)
    args, _ = parser.parse_known_args(sys.argv[1:])
    if not args.debug:
        logging.getLogger().disabled = True
    else:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

    analysis = ForensicstoreSigma("/input.forensicstore", "/app/config.yaml")
    statistics = analysis.analyseStore("/rules")

    # sum = 0
    # lis = sorted(statistics.errors.values(),
    #              key=lambda item: item.count, reverse=True)
    # for k in lis:
    #     print(str(k.message) + ": " + str(k.count) +
    #           "\n\t({})".format(k.files[0]))
    #     sum += k.count
    # print(sum)

    info("Handled %s of %s files successfully.", statistics.successFiles, statistics.totalFiles)


if __name__ == '__main__':
    main()
