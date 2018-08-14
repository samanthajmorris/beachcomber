# BeachComber


# What is BeachComber?

BeachComber is an analytic automation tool which compares file behavior logs against malicious behavior signatures in SIGMA format and generates a report outlining the anomalous or malicious behaviors found in the file. BeachComber uses a generic signature format called SIGMA and can therefore be used to incorporate more analytics into AssemblyLine by adding signatures from different log sources. The main purpose of this project is to further enrich analytics in the binary analysis tool and to incorporate more services and analytics into the dynamic analysis.

This repository contains:
o	-SIGMA rule specification in this document

o	-Repository for sigma signatures in the sysmon-rules subfolder

o	-A tool which checks xml logs against the SIGMA rules


# Getting Started

1.	Download or clone the repository
2.	This tool depends on the following Python mpdules: io, json, collections, xmltodict, sys, fnmatch, configparser and yaml. Please ensure these modules are in your Python environment.
3.	Open the config.txt file and perform the following changes:

     a.	Change the paths of ‘config_folder’, ‘alert_document’, ‘indicator_dir’ and ‘eventlog_empty’ to the paths where you unpacked the BeachComber repository
  
     b.	Change ‘event_log’ to the path to the xml event log that you would like to compare against the rules
  
     c.	If you are checking the event log against a directory of indicators other than the ones provided in the repository, change ‘indicator_dir’ to that path
  
     d.	Give an original name to the document path in ‘alert_document’. Note that if this is not changed between runs, the document will contain multiple alert logs separated by the line “Alerts Generated:”
  
4.	Run with the command ‘python script.py’

# The SIGMA Signature
https://github.com/Neo23x0/sigma


Sigma is a generic and open signature format that allows you to describe relevant log events in a straight forward manner. The rule format is very flexible, easy to write and applicable to any type of log file. The main purpose of this project is to provide a structured form in which researchers or analysts can describe their once developed detection methods and make them shareable with others.

Note: For BeachComber, only the title and detection section is required. BeachComber does not yet have the logic to identify different log sources, therefore it will not identify if you are running Sysmon SIGAM signatures against a log that is not a Sysmon event log.

**BeachComber currently is not compatible with the indicator "Suspicious RDP Redirecft Using TSCON" due the formatting, the program cannot find a condition section. Also not compatible for indicators "Executable used by PlugX in Uncommon Location" and "Mimikatz In-Memory" due to complicated conditions which the logic has not been worked out.**

The rules consist of a few required sections and several optional ones.

```
title
status [optional]
description [optional]
author [optional]
references [optional]
logsource
   category [optional]
   product [optional]
   service [optional]
   definition [optional]
   ...
detection
   {search-identifier} [optional]
      {string-list} [optional]
      {field: value} [optional]
   ...
   timeframe [optional]
   condition
fields [optional]
falsepositives [optional]
level [optional]
tags [optional]
...
[arbitrary custom fields]
```

#### Schema:
RxYAML

```
type: //rec
required:
    title:
        type: //str
        length:
            min: 1
            max: 256
    logsource:
        type: //rec
        optional:
            category: //str
            product: //str
            service: //str
            definition: //str
    detection:
        type: //rec
        required:
            condition:
                type: //any
                of:
                    - type: //str
                    - type: //arr
                      contents: //str
                      length:
                          min: 2
        optional:
            timeframe: //str
        rest:
            type: //any
            of:
                - type: //arr
                  contents: //str
                - type: //map
                  values:
                      type: //any
                      of:
                          - type: //str
                          - type: //arr
                            contents: //str
                            length:
                                min: 2
optional:
    status:
        type: //any
        of:
            - type: //str
              value: stable
            - type: //str
              value: testing
            - type: //str
              value: experimental
    description: //str
    author: //str
    references:
        type: //arr
        contents: //str
    fields:
        type: //arr
        contents: //str
    falsepositives:
        type: //any
        of:
            - type: //str
            - type: //arr
              contents: //str
              length:
                  min: 2
    level:
        type: //any
        of:
            - type: //str
              value: low
            - type: //str
              value: medium
            - type: //str
              value: high
            - type: //str
              value: critical
    tags:
        type: //arr
        contents: //str
rest: //any
```

## Components:
### Title:
A brief title for the rule that should contain what the rules is supposed to detect (max. 256 characters)
Status (optional)
Declares the status of the rule:
•	stable: the rule is considered as stable and may be used in production systems or dashboards.
•	test: an almost stable rule that possibly could require some fine tuning.
•	experimental: an experimental rule that could lead to false results or be noisy, but could also identify interesting events.

### Description (optional):
A short description of the rule and the malicious activity that can be detected (max. 65,535 characters)

### Author (optional):
Creator of the rule.

### References (optional):
References to the source that the rule was derived from. These could be blog articles, technical papers, presentations or even tweets.

### Log Source (optional for BeachComber):
This section describes the log data on which the detection is meant to be applied to. It describes the log source, the platform, the application and the type that is required in detection.
It consists of three attributes that are evaluated automatically by the converters and an arbitrary number of optional elements. We recommend using a "definition" value in cases in which further explication is necessary.
•	category - examples: firewall, web, antivirus
•	product - examples: windows, apache, check point fw1
•	service - examples: sshd, applocker
The "category" value is used to select all log files written by a certain group of products, like firewalls or web server logs. The automatic conversion will use the keyword as a selector for multiple indices.
The "product" value is used to select all log outputs of a certain product, e.g. all Windows Eventlog types including "Security", "System", "Application" and the new log types like "AppLocker" and "Windows Defender".
Use the "service" value to select only a subset of a product's logs, like the "sshd" on Linux or the "Security" Eventlog on Windows systems.
The "definition" can be used to describe the log source, including some information on the log verbosity level or configurations that have to be applied. It is not automatically evaluated by the converters but gives useful advice to readers on how to configure the source to provide the necessary events used in the detection.
You can use the values of 'category, 'product' and 'service' to point the converters to a certain index. You could define in the configuration files that the category 'firewall' converts to ```( index=fw1* OR index=asa* ) ```during Splunk search conversion or the product 'windows' converts to ```"_index":"logstash-windows*" ``` in ElasticSearch queries.
Instead of referring to particular services, generic log sources may be used, e.g.:
```
category: process_creation
product: windows
```
Instead of definition of multiple rules for Sysmon, Windows Security Auditing and possible product-specific rules.

### Detection:
A set of search-identifiers that represent searches on log data

#### Search-Identifier
A definition that can consist of two different data structures - lists and maps.
General
•	All values are treated as case-insensitive strings
•	You can use wildcard characters '*' and '?' in strings
•	Regular expressions are case-sensitive by default
•	You don't have to escape characters except the string quotation marks '

#### Lists
The lists contain strings that are applied to the full log message and are linked with a logical 'OR'.
Example: Matches on 'EvilService' or 'svchost.exe -n evil'
```
detection:
  keywords:
    - EVILSERVICE
    - svchost.exe -n evil
```

#### Maps
Maps (or dictionaries) consist of key/value pairs, in which the key is a field in the log data and the value a string or integer value. Lists of maps are joined with a logical 'OR'. All elements of a map are joined with a logical 'AND'.
Examples:
Matches on Eventlog 'Security' and ( Event ID 517 or Event ID 1102 )
```
detection:
  selection:
    - EventLog: Security
      EventID:
        - 517
        - 1102
condition: selection
```
Matches on Eventlog 'Security' and Event ID 4679 and TicketOptions 0x40810000 andTicketEncryption 0x17
```
detection:
   selection:
      - EventLog: Security
        EventID: 4769
        TicketOptions: '0x40810000'
        TicketEncryption: '0x17'
condition: selection
```

#### Special Field Values
There are special field values that can be used.
•	An empty value is defined with ''
•	A null value is defined with null
OBSOLETE: An arbitrary value except null or empty cannot be defined with not nullanymore
The application of these values depends on the target SIEM system.
To get an expression that say not null you have to create another selection and negate it in the condition.
Example:
```
detection:
   selection:
      EventID: 4738
   filter:
      PasswordLastSet: null
condition:
   selection and not filter
```

#### TimeFrame
A relative time frame definition using the typical abbreviations for day, hour, minute, second.
Examples:
```
15s  (15 seconds)
30m  (30 minutes)
12h  (12 hours)
7d   (7 days)
3M   (3 months)
```
The time frame is defined in the timeframe attribute of the detection section.
Note: The time frame is often a manual setting that has to be defined within the SIEM system and is not part of the generated query.

### Condition:
The condition is the most complex part of the specification and will be subject to change over time and arising requirements. In the first release it will support the following expressions.

#### Logical AND/OR
```
keywords1 or keywords2
```

#### 1/all of search-identifier
Same as just 'keywords' if keywords are defined in a list. X may be:
o	1 (logical or across alternatives)
o	all (logical and across alternatives)
Example: ```all of keywords``` means that all items of the list keywords must appear, instead of the default behaviour of any of the listed items.

#### 1/all of them
Logical OR ```(1 of them)``` or AND ```(all of them)``` across all defined search identifiers. The search identifiers themselves are logically linked with their default behaviour for maps (AND) and lists (OR).
Example: ```1 of them means``` that one of the defined search identifiers must appear.

#### 1/all of search-identifier-pattern
Same as 1/all of them, but restricted to matching search identifiers. Matching is done with * wildcards (any number of characters) at arbitrary positions in the pattern.
Examples:
```
o	1 of selection* and keywords
o	any of selection* and not filters
```

#### Negation with 'not'
```
keywords and not filters
```

#### Pipe
```
search_expression | aggregation_expression
```
A pipe indicates that the result of search_expression is aggregated by aggregation_expression and possibly compared with a value
The first expression must be a search expression that is followed by an aggregation expression with a condition.

#### Brackets
```
selection1 and (keywords1 or keywords2)
```

#### Aggregation expression
agg-function(agg-field) [ by group-field ] comparison-op value
agg-function may be:
o	count
o	min
o	max
o	avg
o	sum
All aggregation functions except count require a field name as parameter. The count aggregation counts all matching events if no field name is given. With field name it counts the distinct values in this field.
Example: ```count(UserName) by SourceWorkstation > 3```
This comparison counts distinct user names grouped by SourceWorkstations.

#### Near aggregation expression
near search-id-1 [ [ and search-id-2 | and not search-id-3 ] ... ]
This expression generates (if supported by the target system and backend) a query that recognizes search_expression (primary event) if the given conditions are or are not in the temporal context of the primary event within the given time frame.

Operator Precedence (least to most binding)
•	|
•	or
•	and
•	not
•	x of search-identifier
•	( expression )

If multiple conditions are given, they are logically linked with OR.

### Fields (optional for BeachComber):
A list of log fields that could be interesting in further analysis of the event and should be displayed to the analyst.

### FalsePositives (optional for BeachComber):
A list of known false positives that may occur.

### Level (optional for BeachComber):
The level contains one of four string values. It serves as a guideline for using the signature and a way to deliver matching events.
     •	low : Interesting event but less likely that it's actually an incident. A security analyst has to review the events and spot anomalies or suspicious indicators. Use this in a dashboard panel, maybe in form of a chart.
     •	medium : Relevant event that should be reviewed manually on a more frequent basis. A security analyst has to review the events and spot anomalies or suspicious indicators. List the events in a dashboard panel for manual review.
     •	high : Relevant event that should trigger an internal alert and has to be reviewed as quickly as possible.
     •	critical : Highly relevant event that triggers an internal alert and causes external notifications (eMail, SMS, ticket). Events are clear matches with no known false positives.
     
### Tags (optional for BeachComber):
A Sigma rule can be categorised with tags. Tags should generally follow this syntax:
     •	Character set: lower-case letters, underscores and hyphens
     •	no spaces
     •	Tags are namespaced, the dot is used as separator. e.g. attack.t1234 refers to technique 1234 in the namespace attack; Namespaces may also be nested
     •	Keep tags short, e.g. numeric identifiers instead of long sentences
     •	If applicable, use predefined tags. Feel free to send pull request or issues with proposals for new tags
     
### Placeholders (optional for BeachComber):
Placeholders can be used to select a set of elements that can be expanded during conversion. Placeholders map a an identifier to a user defined value that can be set in config files for an automatic replacement during conversion runs. Placeholders are meaningful identifiers that users can easily expand themselves.
Examples for placeholders
     •	```%Administrators%``` - Administrative user accounts
     •	```%JumpServers%``` - Server systems used as jump servers
Some SIEM systems allow using so-called "tags" or "search macros" in queries and can integrate Sigma rules with placeholders directly. Others expand the placeholders values to wildcard strings or regular expressions.
Examples for conversions
Splunk
•	```AccountName: %Administrators%``` convert to ```tag=Administrators```
Elastic Search
•	```SourceWorkstation: %JumpServers%``` convert to ```"SourceWorkstation": SRV110[12]```




