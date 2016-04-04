from platform import platform

OS = 'OS'
GENERAL = 'general'
SYSTEM = 'system'
NETWORK = 'network'


def os_slash():
    return '\\' if platform(0, 1).replace('-', ' ').split(' ', 1)[0] == 'Windows' else '/'
