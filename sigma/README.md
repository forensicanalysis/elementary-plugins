# sigma-forensicstore
## analyse_forensicstory.py

Contains the main logic of the matching application.
The application finds all yaml files in a specified path (default is "rules/"), parses them to sql queries and executes these queries against the specified forensicstore (default is "eventlog.forensicstore"). If a query hits a log entry the user is notified.

The application uses the ```SigmaForensicstore``` class. In order to create an instance you need to provide:
1.) The database which contains the logs (default is "eventlog.forensicstore")
2.) The table within the database (default is "eventlog")
3.) The sigma config file (default is "conig.yaml"). The sigma config file is used to configure the behaviour of the sigma parser. In this application it is used, to specify mappings for field names.

To analyse your forensicstore against pre-defined yaml files, you can use the ```analyseStore()``` function of the class ```SigmaForensicstore```. This function expects the path to your rules directory as input and returns statistics about the analysed files.

To run the matching application with default values execute:
```bash
python3 analyse_forensicstory.py
```

## config.yaml

A sigma configuration file. The file is used to specify mappings of filed names. This file needs to be modified to improve the success rate for the pre defined rules.

## SQL.py

This file is mainly a copy of the already existing SQL Backend of the sigma project. It additionaly implements:
1.) aggregation support
2.) full text search support (not implemented for nested conditions, see test_SQL.py for details)

## test_ForensicstoreSigma.py

Contains tests for the ForensicstoreSigma class.

## test_SQL.py

Contains tests for the SQL class.

