# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import logging

from elasticarmor.util import classproperty

__all__ = ['LoggingAware']


class LoggingAware:
    """Logging mixin which provides a convenience property and methods for lazy logging."""

    @classproperty
    def log(cls):
        """Return a logger instance properly set up for the class utilizing this mixin."""
        try:
            return cls.__log
        except AttributeError:
            cls.__log = logging.getLogger(cls.__module__)
            return cls.__log

    @classmethod
    def is_debugging(cls):
        """Return whether debug logging is enabled."""
        return cls.log.isEnabledFor(logging.DEBUG)
