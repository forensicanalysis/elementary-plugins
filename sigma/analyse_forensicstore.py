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

    def __init__(self, pathForensicstore, nameTable, pathSigmaConfig):

        self.table = nameTable

        if os.path.exists(pathForensicstore):
            self.store = forensicstore.open(pathForensicstore)
        else:
            raise IOError("Forensicstore not found " + pathForensicstore)

        if os.path.exists(pathSigmaConfig):
            self.config = SigmaConfiguration(open(pathSigmaConfig))
        else:
            self.config = None

        self.SQL = ForensicStoreBackend(self.config, self.table)

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
                # print(query)
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


if __name__ == '__main__':
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
    print(json.dumps({"header": header, "template": ""}))

    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', dest='debug', action='store_true', default=False)
    args, _ = parser.parse_known_args()
    if not args.debug:
        logging.getLogger().disabled = True
    else:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

    parser = argparse.ArgumentParser(description="Process forensic images and extract artifacts")
    parser.add_argument(
        "forensicstore",
        help="Input forensicstore"
    )
    my_args, _ = parser.parse_known_args(sys.argv[1:])
    url = os.path.join("/store", os.path.basename(my_args.forensicstore))

    analysis = ForensicstoreSigma(url, "xxx", "/app/config.yaml")
    statistics = analysis.analyseStore("/app/rules")

    # sum = 0
    # lis = sorted(statistics.errors.values(),
    #              key=lambda item: item.count, reverse=True)
    # for k in lis:
    #     print(str(k.message) + ": " + str(k.count) +
    #           "\n\t({})".format(k.files[0]))
    #     sum += k.count
    # print(sum)

    info("Handled %s of %s files successfully.", statistics.successFiles, statistics.totalFiles)
