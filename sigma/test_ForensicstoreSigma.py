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
from unittest.mock import patch, mock_open, MagicMock

from analyse_forensicstore import ForensicstoreSigma
from forensicstore_backend import ForensicStoreBackend
from sigma.configuration import SigmaConfiguration
from sigma.parser.exceptions import SigmaParseError


class TestHandleFile(unittest.TestCase):

    def setUp(self):
        with patch("analyse_forensicstore.ForensicstoreSigma.__init__", return_value=None):
            self.analysis = ForensicstoreSigma(
                "any_forensicstore", "test_table", "any_sigma_config")

    def tearDown(self):
        with patch("analyse_forensicstore.ForensicstoreSigma.__del__", return_value=None):
            del self.analysis

    def test_file_is_no_string(self):
        assert self.analysis.handleFile(True) == False
        assert self.analysis.handleFile(1) == False
        assert self.analysis.handleFile(1.0) == False

    def test_file_not_exists(self):
        assert self.analysis.handleFile("does-not-exist") == False

    def test_file_empty(self):
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data="data")) as mocked_open:
                with patch("analyse_forensicstore.ForensicstoreSigma.generateSqlQuery",
                           return_value=tuple()) as mocked_generate_sql_query:
                    # Expect successful handle, file is empty
                    assert self.analysis.handleFile("any/file")
                    mocked_open.assert_called_with("any/file")
                    mocked_generate_sql_query.assert_called_with(
                        mocked_open.return_value)

    def test_file_content(self):
        self.analysis.store = MagicMock()

        sigma_rule = {"title": "Test", "level": "testing", "detection": {
            "keywords": ["test1", "test2"], "condition": "keywords"}}
        generate_query_return = [("This is a sql query", sigma_rule)]

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data="data")) as mocked_open:
                with patch("analyse_forensicstore.ForensicstoreSigma.generateSqlQuery",
                           return_value=generate_query_return) as mocked_generate_sql_query:
                    with patch("builtins.print") as mocked_print:
                        # Expect successful handle, but no SQL results
                        self.analysis.store.query = MagicMock(return_value=[])
                        assert self.analysis.handleFile("any/file")
                        mocked_open.assert_called_with("any/file")
                        self.analysis.store.query.assert_called_with(
                            "This is a sql query")
                        mocked_generate_sql_query.assert_called_with(
                            mocked_open.return_value)
                        self.assertEqual(mocked_print.call_count, 0)
                        mocked_print.reset_mock()

                        # Expect successful handle, two SQL results
                        self.analysis.store.query.return_value = [
                            {'id': 'faked_return'}, {'id': 'faked_return'}]
                        assert self.analysis.handleFile("any/file")
                        mocked_open.assert_called_with("any/file")
                        self.analysis.store.query.assert_called_with(
                            "This is a sql query")
                        mocked_generate_sql_query.assert_called_with(
                            mocked_open.return_value)
                        assert mocked_print.call_count == 2
                        mocked_print.reset_mock()

                        # Expect successful handle, aggregation result
                        self.analysis.store.query.return_value = [
                            {'agg': 'faked_return'}]
                        assert self.analysis.handleFile("any/file")
                        mocked_open.assert_called_with("any/file")
                        self.analysis.store.query.assert_called_with(
                            "This is a sql query")
                        mocked_generate_sql_query.assert_called_with(
                            mocked_open.return_value)
                        assert mocked_print.call_count == 1


class TestGenerateSqlQuery(unittest.TestCase):

    def setUp(self):
        with patch("analyse_forensicstore.ForensicstoreSigma.__init__", return_value=None):
            self.analysis = ForensicstoreSigma(
                "any_forensicstore", "test_table", "any_sigma_config")
            self.analysis.config = SigmaConfiguration()

    def tearDown(self):
        with patch("analyse_forensicstore.ForensicstoreSigma.__del__", return_value=None):
            del self.analysis

    def test_empty_io_stream(self):
        self.analysis.config = SigmaConfiguration()
        self.analysis.table = "tablename"
        self.analysis.SQL = ForensicStoreBackend(self.analysis.config)

        with patch("builtins.open", mock_open(read_data="")):
            assert self.analysis.generateSqlQuery(open("empty file")) == []

    def test_invalid_io_stream(self):
        self.analysis.config = SigmaConfiguration()
        self.analysis.table = "tablename"
        self.analysis.SQL = ForensicStoreBackend(self.analysis.config)

        with patch("builtins.open", mock_open(read_data="not valid\n\nwhatever")):
            self.assertRaises(
                SigmaParseError, self.analysis.generateSqlQuery, open("invalid file"))

    def test_no_io_stream(self):
        self.assertRaises(
            SigmaParseError, self.analysis.generateSqlQuery, None)
        self.assertRaises(
            SigmaParseError, self.analysis.generateSqlQuery, "this is not an input stream")

    def test_options(self):
        # Setting attributes for testing
        self.analysis.config = SigmaConfiguration()
        self.analysis.table = "tablename"
        self.analysis.SQL = ForensicStoreBackend(self.analysis.config)

        sigma_rule = {"title": "Test", "level": "testing", "detection": {
            "keywords": ["test1", "test2"], "condition": "keywords"}}
        generated_query = "Dummy query"

        with patch("yaml.safe_load_all", return_value=[sigma_rule]) as mock_yaml_load:
            with patch("SQL.SQLBackend.generate", return_value=generated_query) as mock_sql_generate:
                # Test for yaml file containing single rule
                assert self.analysis.generateSqlQuery("any sigma io") == [
                    (generated_query, sigma_rule)]
                mock_yaml_load.assert_called_with("any sigma io")

                # Test for yaml file containing two rules
                mock_yaml_load.return_value = [sigma_rule, sigma_rule]
                assert self.analysis.generateSqlQuery("any sigma io") == [(
                    generated_query, sigma_rule), (generated_query, sigma_rule)]

                assert mock_yaml_load.call_count == 2
                assert mock_sql_generate.call_count == 3


if __name__ == '__main__':
    unittest.main()
