# UnixDaemon | (c) 2013 NETWAYS GmbH | GPLv2+

import sys
import os
import signal
import atexit
import errno
import fcntl
import resource
import logging
import optparse
import subprocess
from pwd import getpwnam
from grp import getgrnam

try:
    from subprocess import DEVNULL
except ImportError:
    DEVNULL = open(os.devnull, 'w')

__all__ = ['UnixDaemon', 'get_daemon_option_parser']

try:
    os.SEEK_SET
except AttributeError:
    # Python < 2.5
    os.SEEK_SET = 0
try:
    MAXFD = os.sysconf('SC_OPEN_MAX')
except:
    MAXFD = 1024
DAEMON_FUNCTIONS = ['start', 'stop', 'status', 'restart', 'reload']


class UnixDaemon(object):
    """Well-behaved unix daemon according to Stevens in [1].
    [1] W. Richard Stevens, "Advanced Programming in the Unix Environment",
        1992, Addison-Wesley"""
    name = None

    def __init__(
            self,
            pidfile,
            umask=0,
            chdir='/',
            user=None,
            group=None,
            detach=False,
            logfile=None,
            **kwargs):
        self._pidfle = os.path.realpath(pidfile)
        self._pidfp = None
        self._pidlocked = False
        self._chdir = os.path.realpath(chdir)
        self._detach = detach
        self._logfile = os.path.realpath(logfile) if logfile else None
        if user:
            self.uid = getpwnam(user).pw_uid
        else:
            self.uid = os.getuid()
        if group:
            self.gid = getgrnam(group).gr_gid
        else:
            self.gid = os.getgid()
        self._umask = umask
        self._stdout = sys.stdout
        self._stderr = sys.stderr
        super(UnixDaemon, self).__init__()

    @property
    def log(self):
        try:
            return self.__log
        except AttributeError:
            self.__log = logging.getLogger(self.name)
            return self.__log

    def _daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                os._exit(0)
        except OSError, e:
            raise Exception('fork #1 failed: {0} ({1})'.format(e.errno,
                                                               e.strerror))
        os.setsid()
        try:
            pid = os.fork()
            if pid > 0:
                os._exit(0)
        except OSError, e:
            raise Exception('fork #2 failed: {0} ({1})' .format(e.errno,
                                                                e.strerror))

    def _sigterm_handler(self, signum, frame):
        sys.exit(0)

    def _atexit(self):
        self.cleanup()
        self._delpid()

    def cleanup(self):
        pass

    def _sighup_handler(self, signum, frame):
        self.log.info('Got signal to reload {0}'.format(self.name))

        try:
            self.handle_reload()
        except Exception as error:
            self.log.error(
                'An error occured while reloading {0}: {1}'
                ''.format(self.name, error))
        else:
            self.log.info('Successfully reloaded {0}'.format(self.name))

    def handle_reload(self):
        pass

    def _delpid(self):
        if not self._pidlocked:
            raise Exception('Trying to unlink PID file while not holding '
                            'lock.')
        try:
            os.unlink(self._pidfle)
        except OSError:
            pass

    def _openpidfile(self):
        try:
            self._pidfp = open(self._pidfle, 'r+')
        except IOError:
            pidpath = os.path.dirname(self._pidfle)
            try:
                os.mkdir(pidpath)
                os.chown(pidpath, self.uid, -1)
            except OSError, e:
                if e.errno != errno.EEXIST:
                    raise e
            self._pidfp = open(self._pidfle, 'w+')
        self._waitpidfile(False)

    def _waitpidfile(self, blocking=True):
        if not self._pidlocked:
            try:
                flags = fcntl.LOCK_EX
                if not blocking:
                    flags |= fcntl.LOCK_NB

                fcntl.flock(self._pidfp.fileno(), flags)
                self._pidlocked = True
            except (OSError, IOError):
                pass

    def _closepidfile(self):
        if self._pidfp != None:
            self._pidfp.close()
        self._pidfp = None
        self._pidlocked = False

    def _getpid(self):
        if self._pidfp == None:
            self._openpidfile()
        if self._pidlocked:
            return None
        try:
            self._pidfp.seek(0, os.SEEK_SET)
            pidstr = self._pidfp.readline()
        except IOError:
            return True
        try:
            return int(pidstr.strip())
        except ValueError:
            return True

    def _writepid(self):
        if not self._pidlocked:
            raise Exception('Trying to write PID file while not holding lock.')
        self._pidfp.seek(0, os.SEEK_SET)
        self._pidfp.truncate()
        self._pidfp.write(str(os.getpid()))
        self._pidfp.flush()

    def _redirect_stream(self, source, target):
        try:
            targetfd = target.fileno()
        except AttributeError:
            targetfd = os.open(target, os.O_CREAT | os.O_APPEND | os.O_RDWR)
        source.flush()
        os.dup2(targetfd, source.fileno())

    def _close_fds(self, but):
        maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        if maxfd == resource.RLIM_INFINITY:
            maxfd = MAXFD
        try:
            os.closerange(3, but)
            os.closerange(but + 1, maxfd)
        except AttributeError:
            # Python < v2.6
            for i in xrange(3, maxfd):
                if i == but:
                    continue
                try:
                    os.close(i)
                except:
                    pass

    def _check_logfile_permissions(self):
        if self._logfile:
            try:
                fp = open(self._logfile, 'a')
            except IOError as error:
                if error.errno == errno.EACCES:
                    self.log.critical('Permission denied to write to logfile `%s`',
                                      self._logfile)
                    sys.exit(1)
                if error.errno == errno.ENOENT:
                    self.log.critical('No such directory: `%s`',
                                      os.path.dirname(self._logfile))
                    sys.exit(1)
                # Not a permission error
                raise
            else:
                fp.close()

    def start(self):
        pid = self._getpid()
        if pid:
            self.log.error('%s already running with pid %i', self.name, pid)
            sys.exit(1)
        self.log.info('Starting %s..', self.name)
        os.umask(self._umask)
        os.chdir(self._chdir)
        os.setgid(self.gid)
        os.setuid(self.uid)
        self.before_daemonize()
        if self._detach:
            self._check_logfile_permissions()
            self._daemonize()
            # self._close_fds(self._pidfp.fileno())
            redirect_to = os.devnull
            if self._logfile and self._logfile != '-':
                for channel in logging.getLogger().handlers:
                    # Find the handler(s) which logs to file
                    try:
                        channel.baseFilename
                    except AttributeError:
                        continue
                    else:
                        if channel.baseFilename == os.path.abspath(self._logfile):
                            if channel.stream is None:
                                # The file handler might have been initialized with delay=True
                                channel.stream = channel._open()
                            redirect_to = channel.stream
            self._redirect_stream(sys.stdin, os.devnull)
            self._redirect_stream(sys.stdout, redirect_to)
            self._redirect_stream(sys.stderr, redirect_to)
        signal.signal(signal.SIGTERM, self._sigterm_handler)
        signal.signal(signal.SIGHUP, self._sighup_handler)
        atexit.register(self._atexit)
        self._writepid()
        if not self._detach:
            self.log.info('Use Control-C to exit')
        try:
            self.run()
        except KeyboardInterrupt:
            if not self._detach:
                self.log.info('Exiting')
        return 0

    def stop(self, ignore_error=False):
        pid = self._getpid()
        if not pid and not ignore_error:
            self.log.error('%s is NOT running', self.name)
            sys.exit(1)
        self.log.info('Waiting for %s to stop..', self.name)
        try:
            if pid and pid != True:
                os.kill(pid, signal.SIGTERM)
                self._waitpidfile()
        except OSError, e:
            if e.errno != errno.ESRCH:
                raise e
        return 0

    def reload(self):
        pid = self._getpid()
        if not pid:
            self.log.error('%s is NOT running', self.name)
            sys.exit(1)
        self.log.info('Issuing reload procedures of %s', self.name)
        if pid != True:
            os.kill(pid, signal.SIGHUP)
        return 0

    def restart(self):
        self.stop(True)
        self._closepidfile()
        return self.start()

    def status(self):
        pid = self._getpid()
        if pid:
            if subprocess.call(['ps', '-p', str(pid)], stdout=DEVNULL, stderr=DEVNULL):
                self.log.info('%s is not running but pidfile exists', self.name)
                exit_code = 1
            else:
                self.log.info('%s is running with pid %i', self.name, pid)
                exit_code = 0
        else:
            self.log.info('Pidfile not found, %s is not running', self.name)
            exit_code = 3

        return exit_code

    def run(self):
        pass

    def before_daemonize(self):
        pass


class UnsupportedDaemonFunction(Exception): pass


class DaemonOptionParser(optparse.OptionParser):

    def parse_args(self, a=None, v=None):
        options, args = optparse.OptionParser.parse_args(self, a, v)
        try:
            if args[0] not in DAEMON_FUNCTIONS:
                raise UnsupportedDaemonFunction()
        except (IndexError, UnsupportedDaemonFunction):
            self.print_usage()
            sys.exit(1)
        return options, args


def get_daemon_option_parser(version=None, chdir='/', prog=None):
    usage = '%prog [options] {0}'.format('|'.join(DAEMON_FUNCTIONS))
    parser = DaemonOptionParser(usage=usage, version=version, prog=prog)
    pidfile = '/var/run/{0}.pid'.format(parser.get_prog_name())
    start_stop_group = optparse.OptionGroup(
        parser, 'Start and stop', 'Here are the options to specify the daemon '
                                  'and how it should start or stop:')
    start_stop_group.add_option(
        '-p', '--pidfile', dest='pidfile', metavar='FILE', default=pidfile,
        help='pidfile FILE [default: %default]')
    start_stop_group.add_option(
        '-u', '--user', dest='user', default=None,
        help='Start/stop the daemon as the user.')
    start_stop_group.add_option(
        '-g', '--group', dest='group', default=None,
        help='Start/stop the daemon as in the group.')
    start_group = optparse.OptionGroup(parser, 'Start',
        'These options are only used for starting daemons:')
    start_group.add_option(
        '-b', '--background', dest='detach', default=False,
        action='store_true', help='Force the daemon into the background.')
    start_group.add_option(
        '-d', '--chdir', dest='chdir', metavar='DIR', default=chdir,
        help='chdir to directory DIR before starting the daemon. '
             '[default: %default]')
    start_group.add_option(
        '-k', '--umask', type='int', dest='umask', default=0,
        help='Set the umask of the daemon. [default: %default]')
    parser.add_option_group(start_stop_group)
    parser.add_option_group(start_group)
    return parser
