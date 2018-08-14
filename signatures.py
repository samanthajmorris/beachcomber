import os
import yaml
import sys


def import_ind(dir_name, fn):
    """
    Imports the indicators from the folder containing all the indicators which is referenced in the config file.
    Creates a file which combines all of the indicators together
    :param dir_name: The directory where the separate yaml files of indicators are kept
    :param fn: The file which will become a file containing all of the indicators
    :return: nothing
    """
    try:
        file_list = []
        for files in os.listdir(dir_name):
            dirfile = os.path.join(dir_name, files)
            if os.path.isfile(dirfile) and str(dirfile) not in file_list:
                file_list.append(dirfile)
        with open(fn, 'w') as f:
            for files in file_list:
                f.write("---\n")
                f.write(open(files).read())
                f.write("...\n")
    except:
        print "Error in Formatting of Indicators: Verify your yaml documents"
        sys.exit(1)


def create_json(yaml_file):
    """
    Turns the file of indicators into a dictionary which can be iterated through
    :param yaml_file: The massive file which contains all of the indicators
    :return: A dictionary version of the yaml file
    """
    try:
        newdict = {}
        with open(yaml_file, 'r') as yaml_in:
            loadyaml = yaml.safe_load_all(yaml_in)
            for item in loadyaml:
                tempdict = {}
                if isinstance(item, dict):
                    for k, v in item.iteritems():
                        if k == 'title':
                            tempkey = v
                        elif k == 'detection':
                            tempdict[k] = v
                    newdict[tempkey] = tempdict
        return newdict
    except yaml.YAMLError as exc:
        print "Error in JSON-ing of Indicators: Verify for yaml documents"
        sys.exit(1)


def get_title(ind):
    """
    Gets the title of the indicator
    :param ind: The indicator
    :return: The title of the indicator
    """
    return ind['title']



def get_condition(ind_info, name):
    """
    Gets the condition string from the indicator for analyze
    :param ind_info: The content of the indicator
    :param name: The name of the indicator
    :return: The condition of the indicator
    """
    try:
        return ind_info['detection']['condition']
    except KeyError:
        print "Error: No Condition Found: " + str(name)
        return "none"



def get_info(ind_info):
    """
    Gets the detection section of the indicator
    :param v: the content of the indicator
    :return: the detection section of the indicator
    """
    return ind_info['detection']



def get_data(ind_info, key):
    """
    Pulls out the data from a specific section in detection. v is the dictionary which contains detection and key is the
    title of the section you want to get the data from (string)
    :param v: The content of the indicator
    :param key: The name of the section you are looking for
    :return: The section labled with the key
    """
    return ind_info['detection'][str(key)]
