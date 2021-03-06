# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import logging
import sys

from elasticarmor import *
from elasticarmor.proxy import ElasticReverseProxy
from elasticarmor.request import ElasticRequest
from elasticarmor.settings import ElasticSettings
from elasticarmor.util.daemon import UnixDaemon, StreamLogger
from elasticarmor.util.mixins import LoggingAware

__all__ = ['ElasticArmor']


class ElasticArmor(UnixDaemon, LoggingAware):
    name = APP_NAME.lower()
    version = VERSION
    settings_class = ElasticSettings

    def __init__(self, *args, **kwargs):
        super(ElasticArmor, self).__init__(*args, **kwargs)

        self._proxy = ElasticReverseProxy(self.settings)
        self.persistent_files.append(self._proxy.socket)

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

    def redirect_stdout(self):
        super(ElasticArmor, self).redirect_stdout()
        sys.stdout = StreamLogger(logging.getLogger(self.name + '.stdout').info)

    def redirect_stderr(self):
        super(ElasticArmor, self).redirect_stderr()
        sys.stderr = StreamLogger(logging.getLogger(self.name + '.stderr').error)

    def before_daemonize(self):
        root_log = logging.getLogger()
        root_log.setLevel(self.settings.log_level)

        if self.settings.detach:
            root_log.handlers = [self.settings.log_handler]
            if self.settings.log_type == 'syslog':
                self.persistent_files.append(root_log.handlers[0].socket)
        elif root_log.isEnabledFor(logging.DEBUG):
            # The default StreamHandler is the only one at this time
            root_log.handlers[0].setFormatter(logging.Formatter(FILE_LOG_FORMAT_DEBUG))


def main():
    logging.basicConfig(level=logging.INFO, format=FILE_LOG_FORMAT)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    return ElasticArmor().invoke()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logging.critical('Interrupt received. Application has been aborted.')
        sys.exit(1)
