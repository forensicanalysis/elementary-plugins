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

import json
import logging
import os
import sys
from datetime import datetime
from sqlite3 import OperationalError

import forensicstore
from sigma.configuration import SigmaConfiguration
from sigma.parser.collection import SigmaCollectionParser
from sigma.parser.exceptions import SigmaParseError

from forensicstore_backend import ForensicStoreBackend


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
                if rule.get('logsource', {}).get('product', '').lower() != "windows":
                    continue
                result = self.store.query(query)
                for element in result:
                    dic = {"name": rule["title"],
                           "subtype": "sigma",
                           "level": rule["level"],
                           "rule": rule,
                           "type": "alert"}
                    if "SystemTime" in element.get("System", {}).get("TimeCreated", {}):
                        t = datetime.fromtimestamp(int(element["System"]["TimeCreated"]["SystemTime"]))
                        dic["time"] = t.isoformat()
                    if "agg" not in element:
                        dic["item_ref"] = element["id"]
                    dic["event"] = element
                    print(json.dumps(dic))
            return True

    def analyseStore(self, path):
        statistics = Statistics()

        for root, _, files in os.walk(path):
            for name in files:
                info(name)  # TODO
                print(name)  # TODO
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
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

    analysis = ForensicstoreSigma("/input/input.forensicstore", "/app/config.yaml")
    statistics = analysis.analyseStore("/input/rules")

    info("Handled %s of %s files successfully.", statistics.successFiles, statistics.totalFiles)


if __name__ == '__main__':
    os.symlink("/input/forensicstore", "/input/input.forensicstore")
    main()
