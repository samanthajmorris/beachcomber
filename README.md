# beachComber

# What is BeachComber

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

#The SIGMA Signature

Sigma is a generic and open signature format that allows you to describe relevant log events in a straight forward manner. The rule format is very flexible, easy to write and applicable to any type of log file. The main purpose of this project is to provide a structured form in which researchers or analysts can describe their once developed detection methods and make them shareable with others.

Note: For BeachComber, only the title and detection section is required. BeachComber does not yet have the logic to identify different log sources, therefore it will not identify if you are running Sysmon SIGAM signatures against a log that is not a Sysmon event log.

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

Schema:
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

