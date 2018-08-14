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
