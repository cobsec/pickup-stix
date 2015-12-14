from ConfigParser import ConfigParser

def settings(section):
    dict1 = {}
    Config = ConfigParser()
    Config.read('./config.ini')
    options = Config.options(section)
    for option in options:
        try:
            tmp = Config.get(section, option)
            if tmp == 'True' or tmp == 'False':
                dict1[option] = Config.getboolean(section, option)
            else:
                dict1[option] = tmp

            if dict1[option] == -1:
                DebugPrint("skip: %s" % option)
        except:
            print("exception on %s!" % option)
            dict1[option] = None
    return dict1
