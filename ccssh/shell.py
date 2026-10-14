"""
 Interactive shell over a ShellSession: an `ssh host` experience.

 Single-reader model: a background pump thread owns transport receives and
 writes server output to stdout/stderr; the main thread forwards stdin.
 Terminal is put into raw mode (POSIX) so editors, arrows and Ctrl-C behave;
 SIGWINCH propagates the new size via window-change. The stdin loop polls
 with select(2) so a server-side close (e.g. remote bash exiting after
 Ctrl+D) ends the session promptly instead of hanging on a stdin read.
"""
from __future__ import annotations

import os
import select
import shutil
import signal
import sys
import threading

from ccssh import channel as CH
from ccssh import wire as W
from ccssh.transport import CCSSHError


def _termsize() -> tuple[int, int]:
    s = shutil.get_terminal_size()
    return max(1, s.columns), max(1, s.lines)


def _write_all(fd: int, data: bytes) -> None:
    """Write the full buffer, retrying partial writes (EAGAIN-safe)."""
    mv = memoryview(data)
    while mv:
        n = os.write(fd, mv)
        if n <= 0:
            raise OSError("short write to output")
        mv = mv[n:]


def run_interactive(client, sess=None, *, pty: bool = True, command: str | None = None, stdin_fd: int | None = None, forward_agent: bool = False, x11: bool = False, x11_trusted: bool = False) -> int:
    """
     Run a shell session interactively. Opens one if not given.

     With command set, runs it on a pty channel instead of a shell
     (`ssh -t host command`). With pty=False no pty is requested
     (`ssh -T`). stdin_fd overrides standard input (`ssh -n` passes
     /dev/null). `forward_agent` (`ssh -A`) and `x11` (`ssh -X`, trusted
     with `x11_trusted` for `ssh -Y`) are forwarded to open_shell for a
     fresh session and ignored when sess is already open. Returns the
     remote exit status (0 when none is sent). Restores the terminal on
     all exits.
    """
    own = sess is None
    if own:
        cols, rows = _termsize()
        sess = client.open_shell(cols=cols, rows=rows, pty=pty, command=command,
                                 forward_agent=forward_agent, x11=x11,
                                 x11_trusted=x11_trusted)
    if sess is None:
        raise CCSSHError("no shell session")
    t = client._t
    if t is None:
        raise CCSSHError("connection closed")
    done = threading.Event()
    err: list[BaseException] = []
    # Through the mux when one is active (forwarding shares the
    # connection); direct transport reads otherwise (test fakes included).
    _rx = getattr(client, "_rx", None)

    def _recv_one():
        if callable(_rx):
            return _rx(sess.chan)
        return t.recv_packet()
    if stdin_fd is None:
        stdin_fd = sys.stdin.fileno() if hasattr(sys.stdin, "fileno") else -1
    stdin_no = stdin_fd if stdin_fd >= 0 else 0
    tty_mode = stdin_fd >= 0 and sys.stdin.isatty()
    old_attrs = None

    def pump() -> None:
        try:
            while not done.is_set():
                try:
                    p = _recv_one()
                except Exception as e:
                    err.append(e)
                    done.set()
                    break
                if not p:
                    continue
                m = p[0]
                try:
                    rr = W.Reader(p)
                    rr.byte()
                    want = getattr(sess, "chan", sess.srv)
                    if m == CH.MSG_CHANNEL_DATA:
                        if rr.u32() != want:
                            continue
                        chunk = rr.string()
                        _write_all(1, chunk)
                        try:
                            add = getattr(sess, "add_consumed", None)
                            if callable(add):
                                add(len(chunk))
                            else:
                                sess.consumed += len(chunk)
                        except AttributeError:
                            pass
                        sess.window_adjust()
                    elif m == CH.MSG_CHANNEL_EXTENDED_DATA:
                        if rr.u32() != want:
                            continue
                        if rr.u32() != 1:
                            continue
                        chunk = rr.string()
                        _write_all(2, chunk)
                        # stderr consumes the same server window as stdout:
                        # without crediting it, >2MB on stderr deadlocks.
                        try:
                            add = getattr(sess, "add_consumed", None)
                            if callable(add):
                                add(len(chunk))
                            else:
                                sess.consumed += len(chunk)
                        except AttributeError:
                            pass
                        sess.window_adjust()
                    elif m == CH.MSG_WINDOW_ADJUST:
                        if rr.u32() != want:
                            continue
                        sess.credit(rr.u32())
                    elif m == CH.MSG_CHANNEL_REQUEST:
                        if rr.u32() != want:
                            continue
                        name = rr.string()
                        if name in (b"exit-status", b"exit-signal"):
                            rr.bool()
                            if name == b"exit-status":
                                try:
                                    sess.exit_status = rr.u32()
                                except Exception:
                                    pass
                            else:
                                # A signalled remote process: ssh reports 128
                                # (unknown layouts can't be parsed for a
                                # FAILURE reply, so anything else is ignored).
                                sess.exit_status = 128
                    elif m == CH.MSG_CHANNEL_EOF:
                        if rr.u32() != want:
                            continue
                        sess.eof_received = True
                    elif m == CH.MSG_CHANNEL_CLOSE:
                        if rr.u32() != want:
                            continue
                        _peer_closed = getattr(sess, "_peer_closed", None)
                        if callable(_peer_closed):
                            try:
                                _peer_closed()
                            except Exception:
                                pass
                        done.set()
                        break
                    elif m == 20:  # no rekey with an open channel (see exec)
                        err.append(RuntimeError("peer started rekey with an open channel"))
                        done.set()
                        break
                    # IGNORE/DEBUG/GLOBAL_REQUEST never reach here (transport).
                except Exception as e:
                    err.append(e)
                    done.set()
                    break
        finally:
            done.set()

    th = threading.Thread(target=pump, daemon=True)
    if tty_mode:
        try:
            import termios
            import tty as _tty
            old_attrs = termios.tcgetattr(stdin_fd)
            _tty.setraw(stdin_fd)
        except Exception:
            old_attrs = None
            tty_mode = False

    def _on_winch(_signo, _frame) -> None:
        # No pty was allocated (ssh -T): window-change is meaningless.
        if getattr(sess, "no_pty", False):
            return
        try:
            cols, rows = _termsize()
            sess.window_change(cols, rows)
        except Exception:
            pass

    old_winch = None
    _sigwinch = getattr(signal, "SIGWINCH", None)  # None on Windows
    if tty_mode and _sigwinch is not None:
        try:
            old_winch = signal.signal(_sigwinch, _on_winch)
        except Exception:
            old_winch = None
    stdin_open = True
    try:
        th.start()
        while not done.is_set():
            try:
                ready, _, _ = select.select([stdin_no], [], [], 0.2)
            except (OSError, ValueError):
                ready = [stdin_no] # not selectable: blocking read fallback
            if done.is_set(): # server closed first (e.g. after Ctrl+D)
                break
            if not ready:
                continue
            try:
                chunk = os.read(stdin_no, 4096)
            except (OSError, ValueError):
                chunk = b""
            if not chunk:
                if stdin_open: # stdin EOF -> half-close, keep reading output
                    stdin_open = False
                    sess.send_eof()
                    # Wait for the server to close (bounded: no infinite hang
                    # if the shell ignores EOF).
                    import time as _time
                    _deadline = _time.monotonic() + 10.0
                    while not done.is_set() and _time.monotonic() < _deadline:
                        done.wait(0.05)
                    if not done.is_set():
                        try:
                            sess.close()
                        except Exception:
                            pass
                break
            try:
                sess.send(chunk)
            except Exception as e:
                err.append(e)
                break
        done.wait()
        th.join(timeout=5)
    except KeyboardInterrupt:
        pass
    finally:
        done.set()
        sess.close()
        if old_winch is not None and _sigwinch is not None:
            try:
                signal.signal(_sigwinch, old_winch)
            except Exception:
                pass
        if old_attrs is not None:
            try:
                import termios
                termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_attrs)
                sys.stdout.write("\n")
                sys.stdout.flush()
            except Exception:
                pass
    if err and sess.exit_status is None:
        raise err[0]
    return sess.exit_status if sess.exit_status is not None else 0
