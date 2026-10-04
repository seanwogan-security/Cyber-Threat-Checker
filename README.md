Summarization of the project 

This instrument serves two main purposes: 

1\. Powershell Component 

Collates artifacts from the system: 

Active process and network (TCP) connections 

JSON file called sample\_data/artifacts stores the collected information. 

\- Indicates: 

\- pipelines and cmdlets (`Get-Process, Get-NetTCPConnection`) 

Personal PowerShell objects; property filtering and selection 

Network and process audits: forensic investigation 

2\. Python Sect. 

Reads the PowerShell-produced JSON file, identifies unique remote IP addresses, and confirms each IP using the VirusTotal Threat Intelligence API. 

Generates a report: 

\- The result in JSON format (`reports/analysis\_report.json`) 

The terminal summary of the analyst 

\- Shows: 

Data structures comprise dictionaries, sets, and lists. 

Conditionals and loops 

JSON parsing and file input/output 

Managing mistakes—try/except 

Requests are the external library calls. 

Use of the true security API, VirusTotal 

--

