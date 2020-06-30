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

import re

from sigma.backends.sqlite import SQLiteBackend


class ForensicStoreBackend(SQLiteBackend):
    # Expression of queries for null values or non-existing fields. %s is field name
    nullExpression = "-json_extract(json, '$.%s')=*"
    # Expression of queries for not null values. %s is field name
    notNullExpression = "json_extract(json, '$.%s')=*"
    # Syntax for field/value conditions. First %s is fieldname, second is value
    mapExpression = "json_extract(json, '$.%s') = %s"
    # Syntax for field/value conditions. First %s is fieldname, second is value
    mapMulti = "json_extract(json, '$.%s') IN %s"
    # Syntax for swapping wildcard conditions: Adding \ as escape character
    mapWildcard = "json_extract(json, '$.%s') LIKE %s ESCAPE \'\\\'"
    # Syntax for sourcetype
    mapSource = "json_extract(json, '$.%s')=%s"

    mapFullTextSearch = "json LIKE \"%%%s%%\""

    def __init__(self, sigmaconfig):
        super().__init__(sigmaconfig, "elements")
        self.mappingItem = False

    def generateQuery(self, parsed):
        result = self.generateNode(parsed.parsedSearch)
        if parsed.parsedAgg:
            # Handle aggregation
            fro, whe = self.generateAggregation(parsed.parsedAgg, result)
            return "SELECT json FROM {} WHERE {}".format(fro, whe)

        return "SELECT json FROM elements WHERE json_extract(json, '$.type') = 'eventlog' AND {}".format(result)

    def generateFTS(self, value):
        if re.search(r"((\\(\*|\?|\\))|\*|\?|_|%)", value):
            raise NotImplementedError(
                "Wildcards in SQlite Full Text Search not implemented")
        return self.mapFullTextSearch % value

    def generateANDNode(self, node):

        if self.requireFTS(node):
            fts = self.andToken.join(self.generateFTS(self.cleanValue(val))
                                     for val in node)
            return fts

        generated = [self.generateNode(val) for val in node]
        filtered = [g for g in generated if g is not None]
        if filtered:
            return self.andToken.join(filtered)
        else:
            return None

    def generateORNode(self, node):

        if self.requireFTS(node):
            fts = self.orToken.join(self.generateFTS(self.cleanValue(val))
                                    for val in node)
            return fts

        generated = [self.generateNode(val) for val in node]
        filtered = [g for g in generated if g is not None]
        if filtered:
            return self.orToken.join(filtered)
        else:
            return None
