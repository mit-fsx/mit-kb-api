import logging
import os
import sys

from ConfigParser import SafeConfigParser, NoOptionError, NoSectionError

logger = logging.getLogger('kb_api.config')

class ConfigurationError(Exception):
    pass

class _APIConfig(SafeConfigParser):
    def __init__(self):
        SafeConfigParser.__init__(self)
        filename = os.getenv('KB_API_CONFIG', None)
        if filename is None:
            raise ConfigurationError("KB_API_CONFIG not in environment")
        try:
            with open(filename, 'r') as f:
                self.readfp(f)
        except IOError as e:
            raise ConfigurationError("Could not load configuration file: {0}".format(e))

    def get(self, section, option, *args):
        if len(args) > 1:
            raise ValueError("APIConfig.get(section, option, [default])")
        try:
            return SafeConfigParser.get(self, section, option)
        except (NoOptionError, NoSectionError) as e:
            if len(args) > 0:
                return args[0]
            raise

    @property
    def default_permissions(self):
        if not self.has_section('DefaultPermissions'):
            return {}
        return dict(self.items('DefaultPermissions'))

    @property
    def anonymous_permissions(self):
        if not self.has_section('AnonymousPermissions'):
            return {}
        return dict(self.items('AnonymousPermissions'))

APIConfig = _APIConfig()
