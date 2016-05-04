# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import logging
import sys

from elasticarmor import *
from elasticarmor.proxy import ElasticReverseProxy
from elasticarmor.request import ElasticRequest
from elasticarmor.settings import Settings
from elasticarmor.util.daemon import UnixDaemon
from elasticarmor.util.mixins import LoggingAware


__all__ = ['ElasticArmor']


class ElasticArmor(UnixDaemon, LoggingAware):
    name = APP_NAME.lower()

    def __init__(self, *args, **kwargs):
        super(ElasticArmor, self).__init__(*args, **kwargs)

        self._proxy = ElasticReverseProxy()

    def cleanup(self):
        self.log.info('Shutting down reverse proxy...')
        self._proxy.shutdown()

    def handle_reload(self):
        self.log.info('Reloading request handler caches...')
        ElasticRequest.clear_caches()
        if self._proxy.auth.group_backends:
            self.log.info('Reloading group membership cache...')
            for backend in self._proxy.auth.group_backends:
                try:
                    backend.clear_cache()
                except AttributeError:
                    pass

    def run(self):
        self.log.info('Launching reverse proxy...')
        self._proxy.launch()

    def before_daemonize(self):
        settings = Settings()
        root_log = logging.getLogger()
        root_log.setLevel(settings.log_level)

        if settings.detach:
            root_log.handlers = [settings.log_handler]
        elif root_log.isEnabledFor(logging.DEBUG):
            # The default StreamHandler is the only one at this time
            root_log.handlers[0].setFormatter(logging.Formatter(FILE_LOG_FORMAT_DEBUG))


def main():
    logging.basicConfig(level=logging.INFO, format=FILE_LOG_FORMAT)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    settings = Settings()
    daemon = ElasticArmor(settings.pidfile, settings.umask, settings.chdir,
                          settings.user, settings.group, settings.detach)
    return getattr(daemon, settings.arguments[0])()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logging.critical('Interrupt received. Application has been aborted.')
        sys.exit(1)
