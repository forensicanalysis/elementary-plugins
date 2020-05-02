# Output backends for sigmac
# Copyright 2019 Jayden Zheng

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import sigma
from sigma.backends.base import SingleTextQueryBackend
from sigma.parser.condition import SigmaAggregationParser,NodeSubexpression, ConditionAND, ConditionOR, ConditionNOT
from sigma.parser.exceptions import SigmaParseError

class SQLBackend(SingleTextQueryBackend):
    """Converts Sigma rule into SQL query"""
    identifier = "sql"
    active = True

    andToken = " AND "                      # Token used for linking expressions with logical AND
    orToken = " OR "                        # Same for OR
    notToken = "NOT "                       # Same for NOT
    subExpression = "(%s)"                  # Syntax for subexpressions, usually parenthesis around it. %s is inner expression
    listExpression = "(%s)"                 # Syntax for lists, %s are list items separated with listSeparator
    listSeparator = ", "                    # Character for separation of list items
    valueExpression = "\"%s\""              # Expression of values, %s represents value
    nullExpression = "-%s=*"                # Expression of queries for null values or non-existing fields. %s is field name
    notNullExpression = "%s=*"              # Expression of queries for not null values. %s is field name
    mapExpression = "%s = %s"               # Syntax for field/value conditions. First %s is fieldname, second is value
    mapMulti = "%s IN %s"                   # Syntax for field/value conditions. First %s is fieldname, second is value
    mapWildcard = "%s LIKE %s escape \'\\\'"# Syntax for swapping wildcard conditions: Adding \ as escape character          
    mapSource = "%s=%s"                     # Syntax for sourcetype
    mapListsSpecialHandling = False         # Same handling for map items with list values as for normal values (strings, integers) if True, generateMapItemListNode method is called with node
    mapListValueExpression = "%s OR %s"     # Syntax for field/value condititons where map value is a list
    mapLength = "(%s %s)"

    def __init__(self, sigmaconfig, table, virtualTable):
        super().__init__(sigmaconfig)
        self.table = table
        self.virtualTable = virtualTable

    def generateANDNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            return self.andToken.join(filtered)
        else:
            return None

    def generateORNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            return self.orToken.join(filtered)
        else:
            return None

    def generateNOTNode(self, node):
        generated = self.generateNode(node.item)
        if generated is not None:
            return self.notToken + generated
        else:
            return None

    def generateSubexpressionNode(self, node):
        generated = self.generateNode(node.items)
        if generated:
            return self.subExpression % generated
        else:
            return None

    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return self.listExpression % (self.listSeparator.join([self.generateNode(value) for value in node]))

    def generateMapItemNode(self, node):
        fieldname, value = node
        transformed_fieldname = self.fieldNameMapping(fieldname, value)
        if "," in self.generateNode(value) and not re.search(r"((\\(\*|\?|\\))|\*|\?|_|%)", self.generateNode(value)):
            return self.mapMulti % (transformed_fieldname, self.generateNode(value))
        elif "LENGTH" in transformed_fieldname:
            return self.mapLength % (transformed_fieldname, value)
        elif type(value) == list:
            return self.generateMapItemListNode(transformed_fieldname, value)
        elif self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            if re.search(r"((\\(\*|\?|\\))|\*|\?|_|%)", self.generateNode(value)):
               return self.mapWildcard % (transformed_fieldname, self.generateNode(self.parseWildcard(value)))
            else:
               return self.mapExpression % (transformed_fieldname, self.generateNode(value))
        elif "sourcetype" in transformed_fieldname:
            return self.mapSource % (transformed_fieldname, self.generateNode(value))
        elif "*" in str(value):
            return self.mapWildcard % (transformed_fieldname, self.generateNode(self.parseWildcard(value)))
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemListNode(self, key, value):
        return "(" + (" OR ".join([self.mapWildcard % (key, self.generateValueNode(self.parseWildcard(item))) for item in value])) + ")"
    
    def generateValueNode(self, node):
        return self.valueExpression % (self.cleanValue(str(node)))

    def generateNULLValueNode(self, node):
        return self.nullExpression % (node.item)

    def generateNotNULLValueNode(self, node):
        return self.notNullExpression % (node.item)

    def fieldNameMapping(self, fieldname, value):
        """
        Alter field names depending on the value(s). Backends may use this method to perform a final transformation of the field name
        in addition to the field mapping defined in the conversion configuration. The field name passed to this method was already
        transformed from the original name given in the Sigma rule.
        """
        return fieldname

    def cleanValue(self, val):
        if "*" == val:
            pass
        elif "*.*.*" in val:
            val = val.replace("*.*.*", "%")
        return val

    def parseWildcard(self, val):
        if not isinstance(val, str):
            return val

        #Single backlashes which are not in front of * or ? are doulbed
        val = re.sub(r"(?<!\\)\\(?!(\\|\*|\?))", r"\\\\", val)

        #Replace _ with \_ because _ is a sql wildcard
        val = re.sub(r'_', r'\_', val)

        #Replace % with \% because % is a sql wildcard
        val = re.sub(r'%', r'\%', val)

        #Replace * with %, if even number of backslashes (or zero) in front of *
        val = re.sub(r"(?<!\\)(\\\\)*(?!\\)\*", r"\1%", val)

        #Replace ? with _, if even number of backsashes (or zero) in front of ?
        val = re.sub(r"(?<!\\)(\\\\)*(?!\\)\?", r"\1_", val)
        return val

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        for parsed in sigmaparser.condparsed:

            query = self.generateQuery(parsed)
            before = self.generateBefore(parsed)
            after = self.generateAfter(parsed)

            result = ""
            if before is not None:
                result = before
            if query is not None:
                result += query
            if after is not None:
                result += after

            return result
    
    def evaluateCondition(self, condition):
        if type(condition) not in  [ConditionAND, ConditionOR, ConditionNOT]:
            raise NotImplementedError("Error in recursive Search logic")

        results = []
        for elem in condition.items:
            if isinstance(elem, NodeSubexpression):
                results.append(self.recursiveFtsSearch(elem))
            if isinstance(elem, ConditionNOT):
                results.append(self.evaluateCondition(elem))
            if isinstance(elem, tuple):
                results.append(False)
            if type(elem) in (str, int, list):
                return True
        return any(results)


    def recursiveFtsSearch(self, subexpression):
        #True: found subexpression, where no fieldname is requested -> full text search
        #False: no subexpression found, where a full text search is needed

        if type(subexpression) in [str, int, list]:
            return True
        elif type(subexpression) in [tuple]:
            return False

        if not isinstance(subexpression, NodeSubexpression):
            raise NotImplementedError("Error in recursive Search logic")

        if isinstance(subexpression.items, NodeSubexpression):
            return self.recursiveFtsSearch(subexpression.items)
        elif type(subexpression.items) in [ConditionAND, ConditionOR, ConditionNOT]:
            return self.evaluateCondition(subexpression.items)
            

    def generateQuery(self, parsed):
        if self.recursiveFtsSearch(parsed.parsedSearch):
            #Need to handle full text search
            if isinstance(parsed.parsedSearch, (str,int)):
                #Searching a string/int
                return self.generateFullTextQuery(self.generateNode(parsed.parsedSearch), parsed)
            elif isinstance(parsed.parsedSearch, NodeSubexpression):
                items = parsed.parsedSearch.items.items
                if isinstance(items, list):
                    if items and all(isinstance(s, str) for s in items):
                        #Searching a list of strings
                        return self.generateFullTextQuery(self.generateNode(parsed.parsedSearch)[1:-1], parsed)
                    elif items and all(isinstance(s, int) for s in items):
                        #Searching a list of integers
                        return self.generateFullTextQuery(self.generateNode(parsed.parsedSearch)[1:-1], parsed)
            raise NotImplementedError("FullTextSearch only implemented on first level")
        else:
            result = self.generateNode(parsed.parsedSearch)

        if parsed.parsedAgg:
            #Handle aggregation
            fro, whe = self.generateAggregation(parsed.parsedAgg, result)
            return "Select * From {} Where {}".format(fro, whe)

        return "Select * From {} Where {}".format(self.table, result)
    
    def generateFullTextQuery(self, search, parsed):
        if not self.virtualTable:
            raise NotImplementedError("Full Text search is not enabled")
                
        search = search.replace('"', '')
        search = '" OR "'.join(search.split(" OR "))
        search = '" AND "'.join(search.split(" AND "))
        search = '"{}"'.format(search)
        search = search.replace('%', '')
        search = search.replace('_', '')
        search = '{} match (\'{}\')'.format(self.virtualTable, search)
              
        if parsed.parsedAgg:
            #Handle aggregation
            temp = self.table
            self.table = self.virtualTable
            fro, whe = self.generateAggregation(parsed.parsedAgg, search)
            self.table = temp
            return "Select * From {} Where {}".format(fro, whe)

        return 'Select * from {} where {}'.format(self.virtualTable, search)


    def generateAggregation(self, agg, where_clausel):
        if not agg:
            return self.table, where_clausel
        
        if  (agg.aggfunc == SigmaAggregationParser.AGGFUNC_COUNT or
            agg.aggfunc == SigmaAggregationParser.AGGFUNC_MAX or
            agg.aggfunc == SigmaAggregationParser.AGGFUNC_MIN or
            agg.aggfunc == SigmaAggregationParser.AGGFUNC_SUM or
            agg.aggfunc == SigmaAggregationParser.AGGFUNC_AVG):

            if agg.groupfield:
                group_by = " Group By {0}".format(self.fieldNameMapping(agg.groupfield, None))
            else:
                group_by = ""

            if agg.aggfield:
                select = "{}({}) as agg".format(agg.aggfunc_notrans, self.fieldNameMapping(agg.aggfield, None))
            else:
                if agg.aggfunc == SigmaAggregationParser.AGGFUNC_COUNT:
                    select = "{}(*) as agg".format(agg.aggfunc_notrans)
                else:
                    raise SigmaParseError("For {} aggregation a fieldname needs to be specified".format(agg.aggfunc_notrans))
            
            temp_table = "(Select {} From {} Where {}{})".format(select, self.table, where_clausel, group_by)
            agg_condition =  "agg {} {}".format(agg.cond_op, agg.condition)

            return temp_table, agg_condition
        
        raise NotImplementedError("{} aggregation not implemented in SQL Backend".format(agg.aggfunc_notrans))