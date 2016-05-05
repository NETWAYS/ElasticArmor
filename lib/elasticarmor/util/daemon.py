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
from grp import getgrnam
from pwd import getpwnam

try:
    from subprocess import DEVNULL
except ImportError:
    DEVNULL = open(os.devnull, 'w')

__all__ = ['UnixDaemon', 'StreamLogger', 'create_daemon_option_parser']

DAEMON_FUNCTIONS = ['start', 'stop', 'status', 'restart', 'reload']


class UnixDaemon(object):
    """Well-behaved unix daemon according to Stevens in [1].

    [1] W. Richard Stevens, "Advanced Programming in the Unix Environment", 1992, Addison-Wesley
    """

    name = 'daemon'
    default_maxfd = 1024

    def __init__(self, pid_file_path, detach=False, user=None, group=None, umask=0, chdir='/'):
        self._pid_locked = False
        self._pid_file = None

        self.chdir = os.path.realpath(chdir)
        self.pid_file_path = os.path.realpath(pid_file_path)
        self.user_id = getpwnam(user).pw_uid if user else os.getuid()
        self.group_id = getgrnam(group).gr_gid if group else os.getgid()
        self.detach = detach
        self.umask = umask

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

        signal.signal(signal.SIGTERM, self._sigterm_handler)
        signal.signal(signal.SIGHUP, self._sighup_handler)
        atexit.register(self._atexit)
        if not self.detach:
            self.log.info('Use Control-C to exit.')

        try:
            self.run()
        except KeyboardInterrupt:
            if not self.detach:
                self.log.info('Exiting...')

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

    def _sighup_handler(self, signum, frame):
        self.log.info('Got signal to reload %s.', self.name)

        try:
            self.handle_reload()
        except Exception:
            self.log.error('An error occurred while reloading %s.', self.name, exc_info=True)
        else:
            self.log.info('Successfully reloaded %s.', self.name)

    def _sigterm_handler(self, signum, frame):
        sys.exit(0)

    def _atexit(self):
        self.cleanup()
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
        elif self._pid_locked:
            return

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


class StreamLogger(object):
    """File-like object which redirects writes to a log handler."""

    def __init__(self, log):
        self.log = log

    def write(self, buf):
        buf = buf.lstrip()
        if buf:
            self.log(buf)


class DaemonOptionParser(optparse.OptionParser):
    """Option parser which validates daemon function arguments."""

    def parse_args(self, args=None, values=None):
        options, args = optparse.OptionParser.parse_args(self, args, values)
        if not args or args[0] not in DAEMON_FUNCTIONS:
            self.print_usage()
            sys.exit(1)

        return options, args


def create_daemon_option_parser(version=None, chdir='/', prog=None):
    """Create and return the option parser for a daemon."""
    usage = '%prog [options] {0}'.format('|'.join(DAEMON_FUNCTIONS))
    parser = DaemonOptionParser(usage=usage, version=version, prog=prog)
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
    start_group.add_option('-d', '--chdir', dest='chdir', metavar='DIR', default=chdir,
                           help='Change to directory DIR before starting the daemon. [default: %default]')
    start_group.add_option('-k', '--umask', type='int', dest='umask', default=0,
                           help='The umask of the daemon. [default: %default]')
    parser.add_option_group(start_group)

    return parser
