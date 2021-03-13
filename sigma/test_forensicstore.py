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
# Author(s): Jonas Plum

import unittest
from unittest.mock import patch

from forensicstore_backend import ForensicStoreBackend
from sigma.config.mapping import FieldMapping
from sigma.configuration import SigmaConfiguration
from sigma.parser.collection import SigmaCollectionParser


class TestFullTextSearch(unittest.TestCase):

    def setUp(self):
        self.basic_rule = {"title": "Test", "level": "testing"}
        self.table = "elements"

    def test_regular_queries(self):
        # Test regular queries
        detection = {"selection": {"fieldname": "test1"}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.fieldname\') = "test1"'.format(self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": 4}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.fieldname\') = 4'.format(self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": ["test1", "test2"]}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.fieldname\') IN ("test1", "test2")'.format(self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": [3, 4]}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.fieldname\') IN (3, 4)'.format(self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname1": "test1", "fieldname2": [
            "test2", "test3"]}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND (json_extract(json, \'$.fieldname1\') = "test1" ' \
                          'AND json_extract(json, \'$.fieldname2\') IN ("test2", "test3"))'.format(self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": "test1"}, "filter": {
            "fieldname2": "whatever"}, "condition": "selection and filter"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND (json_extract(json, \'$.fieldname\') = "test1" ' \
                          'AND json_extract(json, \'$.fieldname2\') = "whatever")'.format(self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": "test1"}, "filter": {
            "fieldname2": "whatever"}, "condition": "selection or filter"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND (json_extract(json, \'$.fieldname\') = "test1" ' \
                          'OR json_extract(json, \'$.fieldname2\') = "whatever")'.format(self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": "test1"}, "filter": {
            "fieldname2": "whatever"}, "condition": "selection and not filter"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND (json_extract(json, \'$.fieldname\') = "test1" ' \
                          'AND NOT (json_extract(json, \'$.fieldname2\') = "whatever"))'.format(self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname1": "test1"}, "filter": {
            "fieldname2": "test2"}, "condition": "1 of them"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND (json_extract(json, \'$.fieldname1\') = "test1" ' \
                          'OR json_extract(json, \'$.fieldname2\') = "test2")'.format(self.table)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname1": "test1"}, "filter": {
            "fieldname2": "test2"}, "condition": "all of them"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND (json_extract(json, \'$.fieldname1\') = "test1" ' \
                          'AND json_extract(json, \'$.fieldname2\') = "test2")'.format(self.table)
        self.validate(detection, expected_result)

    def test_modifiers(self):

        # contains
        detection = {"selection": {"fieldname|contains": "test"}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.fieldname\') LIKE "%test%" ESCAPE \'\\\''.format(
            self.table)
        self.validate(detection, expected_result)

        # all
        detection = {"selection": {"fieldname|all": ["test1", "test2"]}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND (json_extract(json, \'$.fieldname\') = "test1" ' \
                          'AND json_extract(json, \'$.fieldname\') = "test2")'.format(self.table)
        self.validate(detection, expected_result)

        # endswith
        detection = {"selection": {"fieldname|endswith": "test"}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.fieldname\') LIKE "%test" ESCAPE \'\\\''.format(self.table)
        self.validate(detection, expected_result)

        # startswith
        detection = {"selection": {"fieldname|startswith": "test"}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.fieldname\') LIKE "test%" ESCAPE \'\\\''.format(self.table)
        self.validate(detection, expected_result)

    def test_aggregations(self):

        # count
        detection = {"selection": {"fieldname": "test"}, "condition": "selection | count() > 5"}
        inner_query = 'SELECT count(*) AS agg FROM {} WHERE json_extract(json, \'$.fieldname\') = "test"'.format(
            self.table)
        expected_result = 'SELECT json FROM ({}) WHERE agg > 5'.format(inner_query)
        self.validate(detection, expected_result)

        # min
        detection = {"selection": {"fieldname1": "test"}, "condition": "selection | min(fieldname2) > 5"}
        inner_query = 'SELECT min(fieldname2) AS agg FROM {} ' \
                      'WHERE json_extract(json, \'$.fieldname1\') = "test"'.format(
            self.table)
        expected_result = 'SELECT json FROM ({}) WHERE agg > 5'.format(inner_query)
        self.validate(detection, expected_result)

        # max
        detection = {"selection": {"fieldname1": "test"}, "condition": "selection | max(fieldname2) > 5"}
        inner_query = 'SELECT max(fieldname2) AS agg FROM {} ' \
                      'WHERE json_extract(json, \'$.fieldname1\') = "test"'.format(self.table)
        expected_result = 'SELECT json FROM ({}) WHERE agg > 5'.format(inner_query)
        self.validate(detection, expected_result)

        # avg
        detection = {"selection": {"fieldname1": "test"}, "condition": "selection | avg(fieldname2) > 5"}
        inner_query = 'SELECT avg(fieldname2) AS agg FROM {} ' \
                      'WHERE json_extract(json, \'$.fieldname1\') = "test"'.format(self.table)
        expected_result = 'SELECT json FROM ({}) WHERE agg > 5'.format(inner_query)
        self.validate(detection, expected_result)

        # sum
        detection = {"selection": {"fieldname1": "test"}, "condition": "selection | sum(fieldname2) > 5"}
        inner_query = 'SELECT sum(fieldname2) AS agg FROM {} ' \
                      'WHERE json_extract(json, \'$.fieldname1\') = "test"'.format(self.table)
        expected_result = 'SELECT json FROM ({}) WHERE agg > 5'.format(inner_query)
        self.validate(detection, expected_result)

        # <
        detection = {"selection": {"fieldname1": "test"}, "condition": "selection | sum(fieldname2) < 5"}
        inner_query = 'SELECT sum(fieldname2) AS agg FROM {} ' \
                      'WHERE json_extract(json, \'$.fieldname1\') = "test"'.format(self.table)
        expected_result = 'SELECT json FROM ({}) WHERE agg < 5'.format(inner_query)
        self.validate(detection, expected_result)

        # ==
        detection = {"selection": {"fieldname1": "test"}, "condition": "selection | sum(fieldname2) == 5"}
        inner_query = 'SELECT sum(fieldname2) AS agg FROM {} ' \
                      'WHERE json_extract(json, \'$.fieldname1\') = "test"'.format(self.table)
        expected_result = 'SELECT json FROM ({}) WHERE agg == 5'.format(inner_query)
        self.validate(detection, expected_result)

        # group by
        detection = {"selection": {"fieldname1": "test"}, "condition": "selection | sum(fieldname2) by fieldname3 == 5"}
        inner_query = 'SELECT sum(fieldname2) AS agg FROM {} ' \
                      'WHERE json_extract(json, \'$.fieldname1\') = "test" GROUP BY fieldname3'.format(self.table)
        expected_result = 'SELECT json FROM ({}) WHERE agg == 5'.format(inner_query)
        self.validate(detection, expected_result)

        # multiple conditions
        detection = {"selection": {"fieldname1": "test"}, "filter": {
            "fieldname2": "tessst"}, "condition": "selection or filter | sum(fieldname2) == 5"}
        inner_query = 'SELECT sum(fieldname2) AS agg FROM {} ' \
                      'WHERE (json_extract(json, \'$.fieldname1\') = "test" ' \
                      'OR json_extract(json, \'$.fieldname2\') = "tessst")'.format(self.table)
        expected_result = 'SELECT json FROM ({}) WHERE agg == 5'.format(inner_query)
        self.validate(detection, expected_result)

    def test_wildcards(self):

        # wildcard: *
        detection = {"selection": {"fieldname": "test*"}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.fieldname\') LIKE '.format(
            self.table) + r'"test%"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        # wildcard: ?
        detection = {"selection": {"fieldname": "test?"}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.fieldname\') LIKE '.format(
            self.table) + r'"test_"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        # escaping:
        detection = {"selection": {"fieldname": r"test\?"}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.fieldname\') LIKE '.format(
            self.table) + r'"test\?"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": r"test\\*"}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.fieldname\') LIKE '.format(
            self.table) + r'"test\\%"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": r"test\*"}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.fieldname\') LIKE '.format(
            self.table) + r'"test\*"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": r"test\\"}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.fieldname\') LIKE '.format(
            self.table) + r'"test\\"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": r"test\abc"}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.fieldname\') LIKE '.format(
            self.table) + r'"test\\abc"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": r"test%"}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.fieldname\') LIKE '.format(
            self.table) + r'"test\%"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname": r"test_"}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.fieldname\') LIKE '.format(
            self.table) + r'"test\_"' + r" ESCAPE '\'"
        self.validate(detection, expected_result)

        # multiple options
        detection = {"selection": {"fieldname": ["test*", "*test"]}, "condition": "selection"}
        opt1 = 'json_extract(json, \'$.fieldname\') LIKE ' + r'"test%"' + r" ESCAPE '\'"
        opt2 = 'json_extract(json, \'$.fieldname\') LIKE ' + r'"%test"' + r" ESCAPE '\'"
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND ({} OR {})'.format(self.table, opt1, opt2)
        self.validate(detection, expected_result)

        detection = {"selection": {"fieldname|all": ["test*", "*test"]}, "condition": "selection"}
        opt1 = 'json_extract(json, \'$.fieldname\') LIKE ' + r'"test%"' + r" ESCAPE '\'"
        opt2 = 'json_extract(json, \'$.fieldname\') LIKE ' + r'"%test"' + r" ESCAPE '\'"
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND ({} AND {})'.format(self.table, opt1, opt2)
        self.validate(detection, expected_result)

    def test_fieldname_mapping(self):
        detection = {"selection": {"fieldname": "test1"}, "condition": "selection"}
        expected_result = 'SELECT json FROM {} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json_extract(json, \'$.mapped_fieldname\') = "test1"'.format(self.table)

        # configure mapping
        config = SigmaConfiguration()
        config.fieldmappings["fieldname"] = FieldMapping(
            "fieldname", "mapped_fieldname")

        self.basic_rule["detection"] = detection

        with patch("yaml.safe_load_all", return_value=[self.basic_rule]):
            parser = SigmaCollectionParser("any sigma io", config, None)
            backend = ForensicStoreBackend(config)

            assert len(parser.parsers) == 1

            for p in parser.parsers:
                self.assertEqual(expected_result.lower(),
                                 backend.generate(p).lower())

    def test_full_text_search(self):
        detection = {"selection": ["test1"], "condition": "selection"}
        expected_result = 'SELECT json FROM {0} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json LIKE "%test1%"'.format(self.table)
        self.validate(detection, expected_result)

        detection = {"selection": [5], "condition": "selection"}
        expected_result = 'SELECT json FROM {0} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND json LIKE "%5%"'.format(self.table)
        self.validate(detection, expected_result)

        detection = {"selection": ["test1", "test2"], "condition": "selection"}
        expected_result = 'SELECT json FROM {0} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND (json LIKE "%test1%" OR json LIKE "%test2%")'.format(self.table)
        self.validate(detection, expected_result)

        detection = {"selection": ["test1"], "filter": ["test2"], "condition": "selection and filter"}
        expected_result = 'SELECT json FROM {0} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND (json LIKE "%test1%" AND json LIKE "%test2%")'.format(self.table)
        self.validate(detection, expected_result)

        detection = {"selection": [5, 6], "condition": "selection"}
        expected_result = 'SELECT json FROM {0} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND (json LIKE "%5%" OR json LIKE "%6%")'.format(self.table)
        self.validate(detection, expected_result)

        detection = {"selection": ["test1"], "filter": [
            "test2"], "condition": "selection or filter"}
        expected_result = 'SELECT json FROM {0} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND (json LIKE "%test1%" OR json LIKE "%test2%")'.format(self.table)
        self.validate(detection, expected_result)

        detection = {"selection": ["test1"], "filter": [
            "test2"], "condition": "selection and filter"}
        expected_result = 'SELECT json FROM {0} ' \
                          'WHERE json_extract(json, \'$.type\') = \'eventlog\' ' \
                          'AND (json LIKE "%test1%" AND json LIKE "%test2%")'.format(self.table)
        self.validate(detection, expected_result)

    def test_full_text_search_aggregation(self):
        # aggregation with fts
        detection = {"selection": ["test"],
                     "condition": "selection | count() > 5"}
        inner_query = 'SELECT count(*) AS agg FROM {0} ' \
                      'WHERE json LIKE "%test%"'.format(self.table)
        expected_result = 'SELECT json FROM ({}) WHERE agg > 5'.format(inner_query)
        self.validate(detection, expected_result)

        detection = {"selection": ["test1", "test2"],
                     "condition": "selection | count() > 5"}
        inner_query = 'SELECT count(*) AS agg FROM {0} ' \
                      'WHERE (json LIKE "%test1%" OR json LIKE "%test2%")'.format(self.table)
        expected_result = 'SELECT json FROM ({}) WHERE agg > 5'.format(inner_query)
        self.validate(detection, expected_result)

        # aggregation + group by + fts
        detection = {"selection": ["test1", "test2"],
                     "condition": "selection | count() by fieldname > 5"}
        inner_query = 'SELECT count(*) AS agg FROM {0} ' \
                      'WHERE (json LIKE "%test1%" OR json LIKE "%test2%") GROUP BY fieldname'.format(self.table)
        expected_result = 'SELECT json FROM ({}) WHERE agg > 5'.format(inner_query)
        self.validate(detection, expected_result)

    def test_not_implemented(self):
        # fts not implemented with wildcards
        detection = {"selection": ["test*"], "condition": "selection"}
        expected_result = NotImplementedError()
        self.validate(detection, expected_result)

        detection = {"selection": ["test?"], "condition": "selection"}
        expected_result = NotImplementedError()
        self.validate(detection, expected_result)

        detection = {"selection": ["test\\"], "condition": "selection"}
        expected_result = NotImplementedError()
        self.validate(detection, expected_result)

        # fts is not implemented for nested condtions
        detection = {"selection": ["test"], "filter": [
            "test2"], "condition": "selection and filter"}  # this is ok
        detection = {"selection": ["test"], "filter": [
            "test2"], "condition": "selection or filter"}  # this is ok
        detection = {"selection": ["test"], "filter": [
            "test2"], "condition": "selection and not filter"}  # this is already nested
        expected_result = "SELECT json FROM elements " \
                          "WHERE json_extract(json, '$.type') = 'eventlog' " \
                          "AND (json LIKE \"%test%\" AND NOT (json LIKE \"%test2%\"))"
        self.validate(detection, expected_result)

        detection = {"selection": ["test"], "filter": [
            "test2"], "condition": "selection and filter and filter"}  # this is nested
        expected_result = "SELECT json FROM elements " \
                          "WHERE json_extract(json, '$.type') = 'eventlog' " \
                          "AND ((json LIKE \"%test%\" AND json LIKE \"%test2%\") AND json LIKE \"%test2%\")"
        self.validate(detection, expected_result)

        detection = {"selection": ["test"], "filter": [
            "test2"], "condition": "selection and filter or filter"}  # this is nested
        expected_result = "SELECT json FROM elements " \
                          "WHERE json_extract(json, '$.type') = 'eventlog' " \
                          "AND ((json LIKE \"%test%\" AND json LIKE \"%test2%\") OR json LIKE \"%test2%\")"
        self.validate(detection, expected_result)

    def validate(self, detection, expectation):

        config = SigmaConfiguration()

        self.basic_rule["detection"] = detection

        with patch("yaml.safe_load_all", return_value=[self.basic_rule]):
            parser = SigmaCollectionParser("any sigma io", config, None)
            backend = ForensicStoreBackend(config)

            assert len(parser.parsers) == 1

            for p in parser.parsers:
                if isinstance(expectation, str):
                    self.assertEqual(expectation, backend.generate(p))
                elif isinstance(expectation, Exception):
                    self.assertRaises(type(expectation), backend.generate, p)


if __name__ == '__main__':
    unittest.main()
