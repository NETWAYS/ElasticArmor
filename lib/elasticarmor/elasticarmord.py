# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import logging
import sys

from elasticarmor import *
from elasticarmor.proxy import ElasticReverseProxy
from elasticarmor.settings import Settings
from elasticarmor.util.daemon import UnixDaemon


__all__ = ['ElasticArmor']


class ElasticArmor(UnixDaemon):
    name = APP_NAME

    def __init__(self, *args, **kwargs):
        super(ElasticArmor, self).__init__(*args, **kwargs)

        self._proxy = ElasticReverseProxy()

    def cleanup(self):
        self.log.info('Shutting down reverse proxy...')
        self._proxy.shutdown()

    def handle_reload(self):
        pass  # TODO: Cache invalidation

    def run(self):
        self.log.info('Launching reverse proxy...')
        self._proxy.launch()

    def before_daemonize(self):
        pass


def main():
    logging.basicConfig(level=logging.ERROR, format=FILE_LOG_FORMAT)
    settings = Settings()
    root_log = logging.getLogger()
    root_log.setLevel(settings.log_level)

    daemon = ElasticArmor(settings.pidfile, settings.umask, settings.chdir, settings.user,
                      settings.group, settings.detach, settings.log_file)

    if settings.detach:
        root_log.handlers = [settings.log_handler]
    elif root_log.isEnabledFor(logging.DEBUG):
        # The default StreamHandler is the only one at this time
        root_log.handlers[0].setFormatter(logging.Formatter(FILE_LOG_FORMAT_DEBUG))

    return getattr(daemon, settings.arguments[0])()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logging.critical('Interrupt received. Application has been aborted.')
        sys.exit(1)
