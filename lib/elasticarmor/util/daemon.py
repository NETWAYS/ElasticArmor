# UnixDaemon | (c) 2013 NETWAYS GmbH | GPLv2+

import atexit
import errno
import fcntl
import logging
import optparse
import os
import resource
import signal
import subprocess
import sys
import threading
from grp import getgrnam
from pwd import getpwnam

try:
    from subprocess import DEVNULL
except ImportError:
    DEVNULL = open(os.devnull, 'w')

__all__ = ['StreamLogger', 'Settings', 'daemon_function', 'UnixDaemon']


class DaemonOptionParser(optparse.OptionParser):
    """Option parser which validates daemon function arguments."""

    def parse_args(self, args=None, values=None):
        options, args = optparse.OptionParser.parse_args(self, args, values)
        if not args or args[0] not in UnixDaemon.functions:
            self.print_usage()
            sys.exit(1)

        return options, args


class StreamLogger(object):
    """File-like object which redirects writes to a log handler."""

    def __init__(self, log):
        self.log = log

    def write(self, buf):
        buf = buf.rstrip()
        if buf:
            self.log(buf)


class Settings(object):
    """Container for application-settings.

    This base class provides options and arguments for a daemon. Use a derived class to
    customize or expand its functionality and set it as settings_class on the daemon.
    """

    _options = None
    _arguments = None

    def __init__(self, app_name, app_version):
        self.app_name = app_name
        self.app_version = app_version

    @property
    def options(self):
        if self._options is None:
            parser = self.create_option_parser(self.app_name, self.app_version)
            self._options, self._arguments = parser.parse_args()

        return self._options

    @property
    def arguments(self):
        if self._arguments is None:
            parser = self.create_option_parser(self.app_name, self.app_version)
            self._options, self._arguments = parser.parse_args()

        return self._arguments

    @property
    def pidfile(self):
        return self.options.pidfile

    @property
    def umask(self):
        return self.options.umask

    @property
    def chdir(self):
        return self.options.chdir

    @property
    def user(self):
        return self.options.user

    @property
    def group(self):
        return self.options.group

    @property
    def detach(self):
        return self.options.detach

    def create_option_parser(self, prog=None, version=None):
        """Create and return the option parser."""
        usage = '%prog [options] {0}'.format('|'.join(UnixDaemon.functions))
        parser = DaemonOptionParser(usage=usage, prog=prog, version=version)
        pid_file_path = '/var/run/{0}.pid'.format(parser.get_prog_name())

        start_stop_group = optparse.OptionGroup(parser, 'Start and Stop', 'Options used to start and stop the daemon:')
        start_stop_group.add_option('-p', '--pidfile', dest='pidfile', metavar='PATH', default=pid_file_path,
                                    help='pidfile PATH [default: %default]')
        start_stop_group.add_option('-u', '--user', dest='user', default=None, help='The user to run the daemon as.')
        start_stop_group.add_option('-g', '--group', dest='group', default=None, help='The group to run the daemon as.')
        parser.add_option_group(start_stop_group)

        start_group = optparse.OptionGroup(parser, 'Start', 'Options used to start the daemon:')
        start_group.add_option('-b', '--background', dest='detach', default=False, action='store_true',
                               help='Force the daemon into the background.')
        start_group.add_option('-d', '--chdir', dest='chdir', metavar='DIR', default='/',
                               help='Change to directory DIR before starting the daemon. [default: %default]')
        start_group.add_option('-k', '--umask', type='int', dest='umask', default=0,
                               help='The umask of the daemon. [default: %default]')
        parser.add_option_group(start_group)

        self.add_additional_options(parser)
        return parser

    def add_additional_options(self, parser):
        """Overwrite this to add additional options to the given parser."""
        pass


def daemon_function(func):
    """Decorator to declare a daemon's method as supported daemon function.

    Usage:
        class YourDaemon(UnixDaemon):
            @daemon_function
            def foo(self):
                print 'bar'

    """
    UnixDaemon.functions.append(func.__name__)
    return func


class UnixDaemon(object):
    """Well-behaved unix daemon according to Stevens in [1].

    [1] W. Richard Stevens, "Advanced Programming in the Unix Environment", 1992, Addison-Wesley
    """

    name = 'daemon'
    version = '1.0'
    default_maxfd = 1024
    settings_class = Settings
    functions = ['start', 'stop', 'status', 'restart', 'reload']

    def __init__(self):
        self._pid_file = None
        self._pid_locked = False

        self.settings = self.settings_class(self.name, self.version)
        self.chdir = os.path.realpath(self.settings.chdir)
        self.pid_file_path = os.path.realpath(self.settings.pidfile)
        self.user_id = getpwnam(self.settings.user).pw_uid if self.settings.user else os.getuid()
        self.group_id = getgrnam(self.settings.group).gr_gid if self.settings.group else os.getgid()
        self.detach = self.settings.detach
        self.umask = self.settings.umask

        self.persistent_files = []
        super(UnixDaemon, self).__init__()

    @property
    def log(self):
        return logging.getLogger(self.name)

    def run(self):
        pass

    def before_daemonize(self):
        pass

    def handle_reload(self):
        pass

    def cleanup(self):
        pass

    def start(self):
        pid = self._read_pid()
        if pid is not None:
            self.log.critical('%s is already running with PID %i.', self.name, pid)
            sys.exit(1)

        self.log.info('Starting %s...', self.name)
        os.umask(self.umask)
        os.chdir(self.chdir)
        os.setgid(self.group_id)
        os.setuid(self.user_id)
        self.before_daemonize()
        if self.detach:
            self.daemonize()
            self.redirect_stdin()
            self.redirect_stdout()
            self.redirect_stderr()
            self._close_unneeded_files()
        self._write_pid()

        signal.signal(signal.SIGTERM, self._apply_cleanup)
        signal.signal(signal.SIGINT, self._apply_cleanup)
        signal.signal(signal.SIGHUP, self._apply_reload)
        atexit.register(self._atexit)
        if not self.detach:
            self.log.info('Use Control-C to exit.')

        self.run()
        return 0

    def reload(self):
        pid = self._read_pid()
        if pid is None:
            self.log.critical('%s is NOT running.', self.name)
            sys.exit(1)

        self.log.info('Issuing reload procedures of %s...', self.name)
        os.kill(pid, signal.SIGHUP)
        return 0

    def restart(self):
        self.stop(ignore_error=True)
        self._close_pid_file()
        return self.start()

    def stop(self, ignore_error=False):
        pid = self._read_pid()
        if pid is None and not ignore_error:
            self.log.critical('%s is NOT running.', self.name)
            sys.exit(1)

        self.log.info('Waiting for %s to stop...', self.name)

        try:
            if pid is not None:
                os.kill(pid, signal.SIGTERM)
                self._lock_pid_file()
        except OSError as e:
            if e.errno != errno.ESRCH:
                self.log.critical('Failed to stop %s.', self.name, exc_info=True)
                sys.exit(1)

        return 0

    def status(self):
        pid = self._read_pid()
        if pid is not None:
            if subprocess.call(['ps', '-p', str(pid)], stdout=DEVNULL, stderr=DEVNULL):
                self.log.info('%s is not running but PID file exists.', self.name)
                exit_code = 1
            else:
                self.log.info('%s is running with PID %i.', self.name, pid)
                exit_code = 0
        else:
            self.log.info('PID file not found or is empty, %s is not running.', self.name)
            exit_code = 3

        return exit_code

    def invoke(self):
        return getattr(self, self.settings.arguments[0])()

    def daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                os._exit(0)
        except OSError:
            self.log.critical('Fork #1 failed.', exc_info=True)
            sys.exit(1)

        os.setsid()

        try:
            pid = os.fork()
            if pid > 0:
                os._exit(0)
        except OSError:
            self.log.critical('Fork #2 failed.', exc_info=True)
            sys.exit(1)

    def redirect_stdin(self):
        os.dup2(os.open(os.devnull, os.O_RDONLY), sys.stdin.fileno())

    def redirect_stdout(self):
        sys.stdout.flush()
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())

    def redirect_stderr(self):
        sys.stderr.flush()
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stderr.fileno())

    def _close_unneeded_files(self):
        maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        if maxfd == resource.RLIM_INFINITY:
            try:
                maxfd = os.sysconf('SC_OPEN_MAX')
            except (AttributeError, ValueError):
                maxfd = self.default_maxfd

        but = [self._pid_file.fileno()]
        for f in self.persistent_files:
            try:
                but.append(f.fileno())
            except AttributeError:
                but.append(f)

        for fd in (fd for fd in xrange(3, maxfd) if fd not in but):
            try:
                os.close(fd)
            except OSError:
                pass  # fd isn't open

    def _apply_reload(self, signum, frame):
        self.log.info('Got signal to reload %s.', self.name)

        try:
            self.handle_reload()
        except Exception:
            self.log.error('An error occurred while reloading %s.', self.name, exc_info=True)
        else:
            self.log.info('Successfully reloaded %s.', self.name)

    def _apply_cleanup(self, signum, frame):
        # If anyone is wondering why this is not part of the atexit handler, move it back there and try
        # to do any serious cleanup tasks which involve thread-synchronisation, then you'll know why..
        threading.Thread(target=self.cleanup, name='CleanupThread').start()
        # And don't dare to put sys.exit(0) back in here. Ever.

    def _atexit(self):
        self._remove_pid_file()

    def _open_pid_file(self):
        try:
            self._pid_file = open(self.pid_file_path, 'r+')
        except IOError:
            pid_file_dir = os.path.dirname(self.pid_file_path)

            try:
                os.mkdir(pid_file_dir)
                os.chown(pid_file_dir, self.user_id, -1)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    self.log.critical('Failed to create PID file directory.', exc_info=True)
                    sys.exit(1)

            self._pid_file = open(self.pid_file_path, 'w+')
        self._lock_pid_file(blocking=False)

    def _lock_pid_file(self, blocking=True):
        if not self._pid_locked:
            try:
                flags = fcntl.LOCK_EX
                if not blocking:
                    flags |= fcntl.LOCK_NB

                fcntl.flock(self._pid_file.fileno(), flags)
                self._pid_locked = True
            except (OSError, IOError) as e:
                if blocking or e.errno != errno.EWOULDBLOCK:
                    self.log.critical('Failed to lock PID.', exc_info=True)
                    sys.exit(1)

    def _read_pid(self):
        if self._pid_file is None:
            self._open_pid_file()
            if self._pid_locked:
                return  # We've got the lock, so there is no other process alive

        try:
            self._pid_file.seek(0, os.SEEK_SET)
            pid = self._pid_file.readline().strip()
        except (IOError, OSError):
            self.log.critical('Failed to read PID.', exc_info=True)
            sys.exit(1)

        try:
            if pid:
                return int(pid)
        except ValueError:
            self.log.critical('Malformed PID: %s', pid)
            sys.exit(1)

    def _write_pid(self):
        if not self._pid_locked:
            raise Exception('Trying to write to PID file while not holding lock')

        self._pid_file.seek(0, os.SEEK_SET)
        self._pid_file.truncate()
        self._pid_file.write(str(os.getpid()))
        self._pid_file.flush()

    def _close_pid_file(self):
        if self._pid_file is not None:
            self._pid_file.close()

        self._pid_file = None
        self._pid_locked = False

    def _remove_pid_file(self):
        if not self._pid_locked:
            raise Exception('Trying to unlink PID file while not holding lock')

        try:
            os.unlink(self.pid_file_path)
        except (IOError, OSError):
            pass
