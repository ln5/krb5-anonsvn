#! /usr/bin/env python

# A generic http server for testing things like OTP methods.

import sys
from getopt import getopt
import urlparse, SocketServer, urllib, BaseHTTPServer
from threading import Thread

def usage():
    print("http-server.py [-f script] host port")
    sys.exit(255)

class ThreadingHTTPServer(SocketServer.ThreadingMixIn,
                          BaseHTTPServer.HTTPServer):
    pass

"""
    def __init__(self, addr, handler, replies, *args, **kwargs):
        BaseHTTPServer.HTTPServer.__init__(addr, handler, *args, **kwargs)
        self.replies = replies
"""

# Globals.
_replies = ['OK']

class server():
    class handler(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_GET(self):
            global _replies
            (scm, netloc, path, params, query, fragment) = \
                  urlparse.urlparse(self.path, 'http')
            print ' *** DEBUG: %s' % repr((scm, netloc, path, params, query, fragment))
            reply = _replies.pop()
            if not _replies:
                _replies.append(reply)
            self.reply200(reply)
                #'DEBUG: %s' % repr((scm, netloc, path, params, query, fragment))))

        def reply200(self, msgs):
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            for l in msgs:
                self.wfile.write(l + '\n')

    def __init__(self, addr, script=None):
        global _replies
        if script:
            if script == '-':
                f = sys.stdin
            else:
                f = open(script, 'r')
            _replies = []
            reply = []
            while True:
                l = f.readline()
                if not l:
                    break
                l = l.strip()
                if l == '':
                    _replies.append(reply)
                    reply = []
                elif l[0] == '#':
                    continue
                else:
                    reply.append(l)
            if f != sys.stdin:
                f.close()
            _replies.reverse()
        self.server = ThreadingHTTPServer(addr, self.handler)
        self.server_thread = Thread(target=self.server.serve_forever)
        self.server_thread.setDaemon(True)
        print _replies

    def start(self):
        self.server_thread.start()
    def stop(self):
        self.server.shutdown()

def main(argv):
    scriptfile = None
    optvals, args = getopt(argv[1:], 'f:')
    for opt, val in optvals:
        if opt == '-f':
            scriptfile = val
    srv = server((args[0], int(args[1])), scriptfile)
    srv.start()
    sys.stdout.write('http-server.py running\n')
    sys.stdout.flush()

    while 1:
        s = sys.stdin.readline()
        if s == 'quit':
            srv.stop()
            print "bye"
            return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
