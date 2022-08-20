#----------HEADER----------#
#-------logiciel_UI--------#

def stoping():
    raise KeyboardInterrupt

def get_radiovalue(radio_value):
    value = radio_value.get()
    return value

def get_pingValue(radio_value_ping):
    value = radio_value_ping.get()
    return value