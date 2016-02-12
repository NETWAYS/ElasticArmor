# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import logging

__all__ = ['LoggingAware']


class LoggingAware:
    """Logging mixin which provides a convenience property for lazy logging."""

    @property
    def log(self):
        """Return a logger instance properly set up for the class utilizing this mixin."""
        try:
            return self.__class__.__log
        except AttributeError:
            self.__class__.__log = logging.getLogger(self.__module__)
            return self.__class__.__log

    def is_debugging(self):
        """Return whether debug logging is enabled."""
        return self.log.isEnabledFor(logging.DEBUG)
