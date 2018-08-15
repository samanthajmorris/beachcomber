from xml.parsers.expat import ExpatError
from io import open
import json
import collections
import xmltodict
import sys



def import_log(origin, new_log):
    """
    Opens the sysmonout.xml file listed in config and converts it to a json file for analysis and places the json file
     in the config folder.
     :param origin: File, the original xml file to read from
    :param new_log: File, the output json file path
    :return: nothing"""
    try:
        with open(origin, "r", encoding='utf-8', errors='ignore') as fp, open(new_log, 'w') as event_json:
            doc = xmltodict.parse(fp.read())
            event_json.write(unicode(json.dumps(doc, ensure_ascii=False)))
    except ExpatError:
        print "Error: Format error in the Log"
        sys.exit(1)
        

def flattened(event):
    """
    Reduces the json logs into only the data that we need.. d will be the log imported as a commandline argument.
    :param event: one event item from the event log file.
    :return: a new version of the event which has been flattened
    """
    items = []
    for key, value in event.items():
        if isinstance(value, collections.MutableMapping):
            items.extend(flattened(value).items())
        else:
            items.append((key, value))
    return dict(items)



def create_event_dict(log):
    """
    Creates a flattened event log which has labeled events which can be iterated through like a dictionary. log is the
    eventlog json imported at the top.
    :param log: the json file containing the event log
    :return: a dictionary version of the log parameter file
    """
    event_dict = {}
    for key, value in log.iteritems():
        content = flattened(value)

    count = 0
    for key, value in content.iteritems():
        for item in value:
            event_dict['Event_' + str(count)] = item
            count = count + 1
    return event_dict


def update_dict(event_dict):
    """
    Re-inserts the data that was removed for formatting.
    :param event_dict: a single event in dictionary format
    :return: a new version of the single including the reformatted code
    """
    tempdict = {}
    data = event_dict['Data']

    for item in data:
        key = 0
        value = 0
        for k, v in item.iteritems():
            if k == '#text':
                value = v
            elif k == '@Name':
                key = v
            else:
                print "Error in Data Section: Formatting"
                break
            if (key != 0) and (value != 0):
                tempdict.update({key: value})

    del event_dict['Data']

    for k, v in tempdict.iteritems():
        event_dict.update({k: v})
    return event_dict
