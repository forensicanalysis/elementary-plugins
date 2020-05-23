from SQLite import SQLiteBackend


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

    def __init__(self, sigmaconfig):
        super().__init__(sigmaconfig, "elements")
        self.mappingItem = False

    def generateQuery(self, parsed):
        self.countFTS = 0
        result = self.generateNode(parsed.parsedSearch)
        if self.countFTS > 1:
            msg = "Match operator ({}) is allowed only once in SQLite, " \
                  "parse rule in a different way:\n{}".format(self.countFTS, result)
            raise NotImplementedError(msg)
        self.countFTS = 0

        if parsed.parsedAgg:
            # Handle aggregation
            fro, whe = self.generateAggregation(parsed.parsedAgg, result)
            return "Select json From {} Where {}".format(fro, whe)

        return "Select json From elements Where json_extract(json, '$.type') = 'eventlog' and {}".format(result)
