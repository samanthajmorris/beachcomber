import json
import configparser
import logs
import matching
import signatures
import sys

config = configparser.ConfigParser()
config.read('config.txt')
ind_dir = config['sources']['indicator_dir']
base = config['sources']['config_folder']
alert_doc = config['sources']['alert_document']
event_log = config['sources']['event_log']
eventlog_empty = config['sources']['eventlog_empty']

logs.import_log(event_log, eventlog_empty)

try:
    with open(eventlog_empty) as x:
        log = json.load(x)
except:
    print "Error with event_json.json."
    sys.exit(1)


yaml_path = base + "/indicators.yaml"
signatures.import_ind(ind_dir, yaml_path)
ind = signatures.create_json(yaml_path)

alert_log = []
alert = []

matching.write_alert("Alerts Generated:" + "\n\n", alert_doc)

event_dict = logs.create_event_dict(log)

for k, v in event_dict.iteritems():
    b = logs.flattened(v)
    c = logs.update_dict(b)
    for ik, iv in ind.iteritems():
        alert_log = matching.analyze(c, ik, iv, alert_log, alert_doc)
    if not alert_log:
            matching.write_alert("No Alerts Generated.")

