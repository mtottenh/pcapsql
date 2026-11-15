#!/usr/bin/env python3
"""Serve the files of one directory over HTTP on 127.0.0.1, with Range requests, and log them.

    range-http-server.py --directory DIR --port-file FILE --log FILE [--port N]

What scripts/remote-test.sh reads captures from through DuckDB's `httpfs`. Python's own
`http.server` answers a Range request with the whole file, and `httpfs` reads a file in ranges,
so this is a server that does what `httpfs` needs:

- GET and HEAD of a regular file directly in DIR (no subdirectories, no listing);
- `Range: bytes=A-B`, `bytes=A-` and `bytes=-N` (one range): 206 with Content-Range, or 416 with
  `Content-Range: bytes */SIZE` for a range that starts past the end;
- `Accept-Ranges: bytes`, Content-Length on every response, and HTTP/1.1 persistent connections;
- 404 for anything else, 405 for other methods.

The port is chosen by the kernel unless --port is given, and written to --port-file once the
server is listening. Every request is one line of --log, written when the response is complete:

    METHOD<TAB>PATH<TAB>RANGE or -<TAB>STATUS<TAB>BODY BYTES SENT

Only the standard library is used.
"""

import argparse
import http.server
import os
import re
import shutil
import sys
import threading
import urllib.parse

RANGE = re.compile(r"^bytes=(\d*)-(\d*)$")


def byte_range(header, size):
    """(first, last) of the bytes `header` asks for, None for the whole file, or "unsatisfiable".

    A header that is not one well-formed byte range is ignored, as RFC 9110 allows.
    """
    if header is None:
        return None
    match = RANGE.match(header.strip())
    if match is None:
        return None
    first, last = match.groups()
    if first == "":
        if last == "":
            return None
        # A suffix: the last N bytes.
        length = int(last)
        if length == 0 or size == 0:
            return "unsatisfiable"
        return max(size - length, 0), size - 1
    first = int(first)
    if first >= size:
        return "unsatisfiable"
    last = size - 1 if last == "" else min(int(last), size - 1)
    if last < first:
        return None
    return first, last


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "pcapsql-range-http-server"

    def do_GET(self):
        self.serve(body=True)

    def do_HEAD(self):
        self.serve(body=False)

    def refuse_method(self):
        # The body of the request, if it has one, is not read: the connection ends here.
        self.close_connection = True
        self.respond(405, {"Allow": "GET, HEAD", "Connection": "close"})

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = refuse_method

    def serve(self, body):
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        name = path[1:]
        file_path = os.path.join(self.server.directory, name)
        if (
            not path.startswith("/")
            or name in ("", ".", "..")
            or "/" in name
            or os.sep in name
            or not os.path.isfile(file_path)
        ):
            self.respond(404, {})
            return
        with open(file_path, "rb") as file:
            size = os.fstat(file.fileno()).st_size
            headers = {
                "Accept-Ranges": "bytes",
                "Content-Type": "application/octet-stream",
                "Last-Modified": self.date_time_string(os.fstat(file.fileno()).st_mtime),
            }
            wanted = byte_range(self.headers.get("Range"), size)
            if wanted == "unsatisfiable":
                headers["Content-Range"] = f"bytes */{size}"
                self.respond(416, headers)
            elif wanted is None:
                self.respond(200, headers, file, 0, size, body)
            else:
                first, last = wanted
                headers["Content-Range"] = f"bytes {first}-{last}/{size}"
                self.respond(206, headers, file, first, last - first + 1, body)

    def respond(self, status, headers, file=None, offset=0, length=0, body=False):
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        # For HEAD, the length the body of the same GET would have.
        self.send_header("Content-Length", str(length))
        self.end_headers()
        sent = 0
        try:
            if body and file is not None and length > 0:
                file.seek(offset)
                remaining = length
                while remaining > 0:
                    chunk = file.read(min(remaining, 1 << 16))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    sent += len(chunk)
                    remaining -= len(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            # The client went away, which a reader that has enough rows may do.
            self.close_connection = True
        finally:
            self.server.record(self.command, self.path, self.headers.get("Range"), status, sent)

    def log_message(self, format, *args):
        # The request log is the file; nothing goes to stderr.
        pass


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, directory, log_path):
        super().__init__(address, Handler)
        self.directory = directory
        self.log = open(log_path, "a", encoding="utf-8")
        self.log_lock = threading.Lock()

    def handle_error(self, request, client_address):
        # A client that hangs up is not news; anything else is.
        if not isinstance(sys.exc_info()[1], ConnectionError):
            super().handle_error(request, client_address)

    def record(self, method, path, range_header, status, sent):
        with self.log_lock:
            self.log.write(f"{method}\t{path}\t{range_header or '-'}\t{status}\t{sent}\n")
            self.log.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--directory", required=True)
    parser.add_argument("--port-file", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--port", type=int, default=0)
    arguments = parser.parse_args()

    server = Server(("127.0.0.1", arguments.port), os.path.abspath(arguments.directory), arguments.log)
    # Written beside the destination and renamed, so that a reader never sees it half-written.
    scratch = arguments.port_file + ".tmp"
    with open(scratch, "w", encoding="utf-8") as file:
        file.write(f"{server.server_address[1]}\n")
    shutil.move(scratch, arguments.port_file)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
