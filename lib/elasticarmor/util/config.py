# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import ConfigParser

from elasticarmor.util import strip_quotes


class Parser(ConfigParser.RawConfigParser):
    """INI Parser derived from ConfigParser.RawConfigParser which is
    aware of default values when accessing a non-existent option."""

    def get(self, section, option):
        """Return the value of the given option located in the given section.

        In contrast to ConfigParser.RawConfigParser.get this will not raise ConfigParser.NoSectionError
        or ConfigParser.NoOptionError if there is a default value configured for the given option.
        """

        try:
            value = ConfigParser.RawConfigParser.get(self, section, option)
        except ConfigParser.NoSectionError as error:
            try:
                return self._defaults[self.optionxform(option)]
            except KeyError:
                raise error
        else:
            try:
                return strip_quotes(value)
            except TypeError:
                return value
