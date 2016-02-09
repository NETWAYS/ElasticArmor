# ReadWriteLock | (c) 2011 NETWAYS GmbH | GPLv2+

from functools import update_wrapper
from multiprocessing import current_process
from threading import current_thread, Condition, Lock
from time import time, sleep

__all__ = ['WouldDeadlock', 'ReadWriteLock', 'ForkAwareRWLock', 'Protector']


class WouldDeadlock(Exception):
    pass


class ReadWriteLock(object):
    """Read-Write lock class. A read-write lock differs from a standard
    threading.RLock() by allowing multiple threads to simultaneously hold a
    read lock, while allowing only a single thread to hold a write lock at the
    same point of time.

    When a read lock is requested while a write lock is held, the reader
    is blocked; when a write lock is requested while another write lock is
    held or there are read locks, the writer is blocked.

    Writers are always preferred by this implementation: if there are blocked
    threads waiting for a write lock, current readers may request more read
    locks (which they eventually should free, as they starve the waiting
    writers otherwise), but a new thread requesting a read lock will not
    be granted one, and block. This might mean starvation for readers if
    two writer threads interweave their calls to acquireWrite() without
    leaving a window only for readers.

    In case a current reader requests a write lock, this can and will be
    satisfied without giving up the read locks first, but, only one thread
    may perform this kind of lock upgrade, as a deadlock would otherwise
    occur. After the write lock has been granted, the thread will hold a
    full write lock, and not be downgraded after the upgrading call to
    acquireWrite() has been match by a corresponding release().

    """
    def __init__(self):
        """Initialize this read-write lock."""

        # Condition variable, used to signal waiters of a change in object
        # state.
        self._condition = Condition(Lock())

        # Initialize with no writers.
        self._writer = -1
        self._writercount = 0
        self._upgradewritercount = 0
        self._pendingwriters = []

        # Initialize with no readers.
        self._readers = {}

        # Set callable to differentiate between threads
        self._current = current_thread

    @property
    def readContext(self):
        """Return a context manager to acquire and release read mode on this lock."""
        return ReadContext(self)

    @property
    def writeContext(self):
        """Return a context manager to acquire and release write mode on this lock."""
        return WriteContext(self)

    def acquireRead(self, timeout=None):
        """Acquire a read lock for the current thread, waiting at most
        timeout seconds or doing a non-blocking check in case timeout is <= 0.

        In case timeout is None, the call to acquireRead blocks until the
        lock request can be serviced.

        In case the timeout expires before the lock could be serviced, a
        RuntimeError is thrown."""

        if timeout is not None:
            endtime = time() + timeout
        me = self._current()
        self._condition.acquire()
        try:
            if self._writer == me:
                # If we are the writer, grant a new read lock, always.
                self._writercount += 1
                return
            while True:
                if self._writer == -1:
                    # Only test anything if there is no current writer.
                    if self._upgradewritercount or self._pendingwriters:
                        if me in self._readers:
                            # Only grant a read lock if we already have one
                            # in case writers are waiting for their turn.
                            # This means that writers can't easily get starved
                            # (but see below, readers can).
                            self._readers[me] += 1
                            return
                        # No, we aren't a reader (yet), wait for our turn.
                    else:
                        # Grant a new read lock, always, in case there are
                        # no pending writers (and no writer).
                        self._readers[me] = self._readers.get(me, 0) + 1
                        return
                if timeout is not None:
                    remaining = endtime - time()
                    if remaining <= 0:
                        # Timeout has expired, signal caller of this.
                        raise RuntimeError("Acquiring read lock timed out")
                    self._condition.wait(remaining)
                else:
                    self._condition.wait()
        finally:
            self._condition.release()

    def acquireWrite(self, timeout=None):
        """Acquire a write lock for the current thread, waiting at most
        timeout seconds or doing a non-blocking check in case timeout is <= 0.

        In case the write lock cannot be serviced due to the deadlock
        condition mentioned above, a WouldDeadlock exception is raised.

        In case timeout is None, the call to acquireWrite blocks until the
        lock request can be serviced.

        In case the timeout expires before the lock could be serviced, a
        RuntimeError is thrown."""

        if timeout is not None:
            endtime = time() + timeout
        me, upgradewriter = self._current(), False
        self._condition.acquire()
        try:
            if self._writer == me:
                # If we are the writer, grant a new write lock, always.
                self._writercount += 1
                return
            elif me in self._readers:
                # If we are a reader, no need to add us to pendingwriters,
                # we get the upgradewriter slot.
                if self._upgradewritercount:
                    # If we are a reader and want to upgrade, and someone
                    # else also wants to upgrade, there is no way we can do
                    # this except if one of us releases all his read locks.
                    # Signal this to the user.
                    raise WouldDeadlock(
                        "Inevitable dead lock, denying write lock"
                        )
                upgradewriter = True
                self._upgradewritercount = self._readers.pop(me)
            else:
                # We aren't a reader, so add us to the pending writers queue
                # for synchronization with the readers.
                self._pendingwriters.append(me)
            while True:
                if not self._readers and self._writer == -1:
                    # Only test anything if there are no readers and writers.
                    if self._upgradewritercount:
                        if upgradewriter:
                            # There is a writer to upgrade, and it's us. Take
                            # the write lock.
                            self._writer = me
                            self._writercount = self._upgradewritercount + 1
                            self._upgradewritercount = 0
                            return
                        # There is a writer to upgrade, but it's not us.
                        # Always leave the upgrade writer the advance slot,
                        # because he presumes he'll get a write lock directly
                        # from a previously held read lock.
                    elif self._pendingwriters[0] == me:
                        # If there are no readers and writers, it's always
                        # fine for us to take the writer slot, removing us
                        # from the pending writers queue.
                        # This might mean starvation for readers, though.
                        self._writer = me
                        self._writercount = 1
                        self._pendingwriters.pop(0)
                        return
                if timeout is not None:
                    remaining = endtime - time()
                    if remaining <= 0:
                        # Timeout has expired, signal caller of this.
                        if upgradewriter:
                            # Put us back on the reader queue. No need to
                            # signal anyone of this change, because no other
                            # writer could've taken our spot before we got
                            # here (because of remaining readers), as the test
                            # for proper conditions is at the start of the
                            # loop, not at the end.
                            self._readers[me] = self._upgradewritercount
                            self._upgradewritercount = 0
                        else:
                            # We were a simple pending writer, just remove us
                            # from the FIFO list.
                            self._pendingwriters.remove(me)
                        raise RuntimeError("Acquiring write lock timed out")
                    self._condition.wait(remaining)
                else:
                    self._condition.wait()
        finally:
            self._condition.release()

    def release(self):
        """Release the currently held lock.

        In case the current thread holds no lock, a ValueError is thrown."""

        me = self._current()
        self._condition.acquire()
        try:
            if self._writer == me:
                # We are the writer, take one nesting depth away.
                self._writercount -= 1
                if not self._writercount:
                    # No more write locks; take our writer position away and
                    # notify waiters of the new circumstances.
                    self._writer = -1
                    self._condition.notify_all()
            elif me in self._readers:
                # We are a reader currently, take one nesting depth away.
                self._readers[me] -= 1
                if not self._readers[me]:
                    # No more read locks, take our reader position away.
                    del self._readers[me]
                    if not self._readers:
                        # No more readers, notify waiters of the new
                        # circumstances.
                        self._condition.notify_all()
            else:
                raise ValueError("Trying to release unheld lock")
        finally:
            self._condition.release()


class ReadContext(object):
    """Context manager to acquire and release read mode of a ReadWriteLock."""

    def __init__(self, lock):
        self.lock = lock

    def __enter__(self):
        self.lock.acquireRead()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.lock.release()


class WriteContext(object):
    """Context manager to acquire and release write mode of a ReadWriteLock."""

    def __init__(self, lock):
        self.lock = lock

    def __enter__(self):
        self.lock.acquireWrite()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not isinstance(exc_type, WouldDeadlock):
            self.lock.release()


class ForkAwareRWLock(ReadWriteLock):
    __writer__ = None
    _writer = property(lambda s: s.__writer__.value,
                       lambda s, v: setattr(s, '__writer__', v)
                                    if s.__writer__ is None else
                                    setattr(s.__writer__, 'value', v))
    __writercount__ = None
    _writercount = property(lambda s: s.__writercount__.value,
                            lambda s, v: setattr(s, '__writercount__', v)
                                         if s.__writercount__ is None else
                                         setattr(s.__writercount__, 'value', v))
    __upgradewritercount__ = None
    _upgradewritercount = property(lambda s: s.__upgradewritercount__.value,
                                   lambda s, v: setattr(s, '__upgradewritercount__', v)
                                                if s.__upgradewritercount__ is None else
                                                setattr(s.__upgradewritercount__, 'value', v))
    _current = lambda s: current_process().pid

    def __init__(self, condition, writer, upgrade_count,
                 writer_count, writers, readers):
        self._upgradewritercount = upgrade_count
        self._writercount = writer_count
        self._pendingwriters = writers
        self._condition = condition
        self._readers = readers
        self._writer = writer

    def __getstate__(self):
        return {'_condition': self._condition, '_readers': self._readers,
                '__upgradewritercount__': self.__upgradewritercount__,
                '_pendingwriters': self._pendingwriters,
                '__writercount__': self.__writercount__,
                '__writer__': self.__writer__}


class Protector(object):
    """
    Basically some sort of advanced decorator. It wraps a method into a read
    lock and the method may upgrade the lock safely even in a recursive manner.
    If the upgrade is not possible the protector handles the case so that every
    read lock that may have been acquired by the protector gets released and the
    pending upgrade can be serviced.

    After all read locks are released the process restarts with the first call
    wherewith the protection was initiated.

    """
    def __init__(self, lock_attr):
        self.lock_attr = lock_attr
        self._recursion_depth = 0

    def __call__(self, func):
        def shield(*args, **kwargs):
            if isinstance(self.lock_attr, basestring):
                self.lock_attr = getattr(args[0], self.lock_attr)
            while True:
                self.lock_attr.acquireRead()
                self._recursion_depth += 1

                try:
                    return func(*args, **kwargs)
                except WouldDeadlock:
                    if self._recursion_depth > 1:
                        raise
                finally:
                    self._recursion_depth -= 1
                    self.lock_attr.release()

                sleep(0.5)
        return update_wrapper(shield, func)
