# PEPackingAnalysisTool
-Work in progress malware analysis program developed in Python
-Statically analyzes a PE executable for characteristics and heuristics
-Utilizes the Elasticsearch engine’s advanced storage and search capabilities
-Creates a document for each sample containing all its features including some data in nested objects
-Data can be used to train a neural network to detect sample properties like packing, obfuscation, malicious vs non-malicious, etc.
-Data within the Elasticsearch database can be visualized using Kibana
