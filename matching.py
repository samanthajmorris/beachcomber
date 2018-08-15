from signatures import *
import fnmatch


def find_matches(event, indi):
    """
    Matches the items in the indicator to the event... Iterates through the sections and if theres a list it iterates
    through that. Uses checkpair to see if the items in the list/dictionary match items in the eventlog.
    :param event: A single event from the eventlog dictonary(the value)
    :param indi: A single indicator from the indicators file
    :return: True if there is a match and false if there is not
    """
    flag = False
    if isinstance(indi, dict):
        for key, value in indi.iteritems():
            if isinstance(value, list):
                for item in value:
                    if not checkpair(event, key, item):
                        flag = False
                    else:
                        flag = True
                        break

            else:
                if not checkpair(event, key, value):
                    return False

                else:
                    flag = True
    else:
        if isinstance(indi, list):
            for item in indi:
                if isinstance(item, dict):
                    for ik, iv in item.iteritems():
                        if not checkpair(event, ik, iv):
                            flag = False
                        else:
                            flag = True
    return flag


def match_basic(event, ind_info):
    """
    Basic matching by calling find_matches and returning True if find_matches is true.
    :param event: A single event from the eventlog dictionary(the value)
    :param info: The content from the indicator- not the name
    :return: The boolean result of find matches on the event and data
    """
    return find_matches(event, ind_info)


def match_1_of_them(event, ind_info):
    """
    Matches for the '1 of them' condition by iterating through all of the sections in detection and as long as the section
    isnt condition it will perform a find_matches on it. Once one hits as true, its done.
    :param event: A single event from the eventlog dictionary (the value)
    :param info: The content from the indicator (not the name)
    :return: True if there is a match and False if not
    """
    detection_section = ind_info['detection']
    for key, value in detection_section.iteritems():
        if key != 'condition':
            section_content = ind_info['detection'][str(key)]
            find_matches(event, section_content)
            if find_matches(event, section_content):
                return True
            else:
                return False


def sel_and_oneof(event, ind_info, name):
    """
    Matches for the 'selection and one of combination' condition. First performs find_matches on the selection section of
    detection and if it returns true, it iterates through all of the other sections which arent selection and performs
    find matches on each section. Once one returns True is is done
    :param event: A signle event from the eventlog dictionary (the value)
    :param ind_info:  the content form the indicator dictionary- without the name
    :param name: The name of the indicator
    :return: True if there is a match and False if there is not
    """
    if isinstance(ind_info, dict):
        if match_basic(event, get_data(ind_info, 'selection')):
            detection_section = ind_info['detection']
            for item in detection_section:
                if (item != 'selection') and (item != 'condition'):
                    item_section = ind_info['detection'][str(item)]
                    find_matches(event, item_section)
                    return find_matches(event, item_section)
        else:
            return False
    else:
        print "Error in Formatting: No dictionary found: " + str(name)
        return False


def meth_match(event, ind_info, name):
    """
    Performs a match for the condition 'methregistry or ( methprocess and not filterprocess )' by calling to match_basic
    for methregistry and then again for the sections in the brackets.
    :param event: A single event from the eventlog dictionary (the value)
    :param ind_info: the content from the indicator dictionary- without the name
    :param name: The name of the indicator
    :return: True if there is a match and False if there is not
    """
    if isinstance(ind_info, dict):
        return match_basic(event, ind_info['detection']['methregistry']) or (
                    match_basic(event, ind_info['detection']['methprocess']) and not match_basic(event,
                                                                                                 ind_info['detection'][
                                                                                                     'filterprocess']))
    else:
        print "Error in Formatting: No dictionary found: " + str(name)
        return False


def all_of_them(event, ind_info, name):
    """
    Iterates through all of the sections and performs find matches on each one. Breaks if one returns False
    :param event: A single event from the eventlog dictionary (the value)
    :param ind_info: The content of the indicator dictionary- without the name
    :param name: The name of the indicator
    :return: True if there is a match and False if there is not
    """
    if isinstance(ind_info, dict):
        sections = ind_info['detection']
        for item in sections:
            z = ind_info['detection'][str(item)]
            find_matches(event, z)
            return find_matches(event, z)

    else:
        print "Error in Formatting: No dictionary found: " + str(name)
        return False


def analyze(event, ind_name, indicator, alert_log, doc):
    """
    Extracts the condition from each indicator in the indicator log and calls the appropriate match method against the
    indicator and the event. If matches, adds alert to the alert_log list for iteration in script.py and adds the indicator
    and indicator information into the alert log document. Event is a single event from the eventlog, ind_name is the name
    of the indicator, indicator is the complete indicator dictionary, alert_log is a list of indicator names which have
    been hit on, doc is the alert log.
    :param event: A single event from the eventlog dictionary (the value)
    :param ind_name: The name of the indicator
    :param indicator: The content of the indicator (wihtout the name)
    :param alert_log: A list of alerts containing the matches
    :param doc: The empty document to be written to which will be the alert log
    :return: the alert log or the list of matches
    """
    # ALERT LOG LIST COULD BE CHANGED TO A HITS VARIABLE OR SOMETHING LESS COMPLEX
    if isinstance(indicator, dict):

        if get_condition(indicator, ind_name) == 'selection':
            if match_basic(event, get_data(indicator, 'selection')) and str(ind_name) not in alert_log:
                alert_log.append(str(ind_name))
                write_alert(str(ind_name), doc)
                write_info(indicator, doc)

        elif get_condition(indicator, ind_name) == 'selection and not filter':
            if match_basic(event, get_data(indicator, 'selection')) and match_basic(event, get_data(indicator,
                                                                                                    'filter')) and str(
                ind_name) not in alert_log:
                alert_log.append(str(ind_name))
                write_alert(str(ind_name), doc)
                write_info(indicator, doc)

        elif get_condition(indicator, ind_name) == 'selection and not exclusion':
            if match_basic(event, get_data(indicator, 'selection')) and match_basic(event, get_data(indicator,
                                                                                                    'exclusion')) and str(
                ind_name) not in alert_log:
                alert_log.append(str(ind_name))
                write_alert(str(ind_name), doc)
                write_info(indicator, doc)

        elif get_condition(indicator, ind_name) == "selection and not falsepositive":
            if match_basic(event, get_data(indicator, 'selection')) and match_basic(event, get_data(indicator,
                                                                                                    'falsepositive')) and str(
                ind_name) not in alert_log:
                alert_log.append(str(ind_name))
                write_alert(str(ind_name), doc)
                write_info(indicator, doc)

        elif get_condition(indicator, ind_name) == '1 of them':
            if match_1_of_them(event, indicator) and str(ind_name) not in alert_log:
                alert_log.append(str(ind_name))
                write_alert(str(ind_name), doc)
                write_info(indicator, doc)

        elif get_condition(indicator, ind_name) == "selection and 1 of combination*":
            if sel_and_oneof(event, indicator, ind_name) and str(ind_name) not in alert_log:
                alert_log.append(str(ind_name))
                write_alert(str(ind_name), doc)
                write_info(indicator, doc)

        elif get_condition(indicator, ind_name) == 'methregistry or ( methprocess and not filterprocess )':
            if meth_match(event, indicator, ind_name) and str(ind_name) not in alert_log:
                alert_log.append(str(ind_name))
                write_alert(str(ind_name), doc)
                write_info(indicator, doc)

        elif get_condition(indicator, ind_name) == 'all of them':
            if all_of_them(event, indicator, ind_name) and str(ind_name) not in alert_log:
                alert_log.append(str(ind_name))
                write_alert(str(ind_name), doc)
                write_info(indicator, doc)

        # else:
        return alert_log


def checkpair(self, key, value):
    """
    Checks to see if a given key and value from the indicator are also in the event.
    :param self: A single event from the event log
    :param key: The type of indicator // A key from the indicator dictionary
    :param value: The indicator // A value from the indicator dictionary
    :return: True if there is a match, false if there is not
    """
    if key in self:
        if '*' in str(value):
            return fnmatch.fnmatch(self[key], value)
        elif self[key] == str(value):
            return True
        else:
            return False

    else:
        return False





def write_alert(string, doc):
    """
    Writes the string to the alert document 'doc'
    :param string: A string to be written to the document
    :param doc: The document that you want the string to be written to
    :return: nothing
    """
    with open(doc, 'a+') as f:
        f.write(string)
        f.write('\n')


def list_event(info, event):
    """
    Turns the event info into a list to be outputted to the alert log. info is the detction section of the event, event is an empty list
    :param info: The content section of an event
    :param event: An empty list
    :return: The list 'event'
    """
    for key, value in info.iteritems():
        if isinstance(value, dict):
            list_event(value, event)
        else:
            line = "{0} : {1}".format(key, value)
            event.append(str(line))
    return event


def write_info(indicator, doc):
    """
    Writes the listed info from list_event method called on indicator into the alert log (doc)
    :param indicator: The indicator the has generated an alert
    :param doc: The alert log document that the alert should be written to
    :return: nothing
    """
    event = []
    info = get_info(indicator)
    info_list = list_event(info, event)
    for item in info_list:
        write_alert(item, doc)
    write_alert('\n', doc)
