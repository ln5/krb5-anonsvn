#! /usr/bin/python

# Copyright (C) 2011 NORDUnet A/S.  All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
# OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import exceptions
from k5test import *
from k5test import _start_daemon, _build_env

YKCLIENT_HOST = 'localhost'
YKCLIENT_PORT = 4711
YKCLIENT_URL = 'http://%s:%d/wsapi/2.0/verify?id=%%d&otp=%%s' % \
               (YKCLIENT_HOST, YKCLIENT_PORT)

otp_krb5_conf = {
    'all' : {
        # Configure ykclient method.
        'realms' : {
            '$realm' : {
                'otp_ykclient_url_template' :
                YKCLIENT_URL,
                'otp_ykclient_client_id' : '1',
            }
        },
        # Enable OTP plugin.
        'plugins' : {
            'enable_only' : 'otp',
            'kdcpreauth' : {'module' : 'otp:preauth/otp.so'},
            'clpreauth' : {'module' : 'otp:preauth/otp.so'},
        }
    }
}

class OathToken:
    HOTP = 1                            # Event-based.
    TOTP = 2                            # Time-based.  NYI.

    def __init__(self, key=0, binary='oathtool', mode=HOTP, digits=6,
                 runfun=None):
        self.key = key
        self.binary = binary
        self.digits = digits
        self.runfun = runfun
        self.counter = 0

    def next_otp(self):
        if not self.runfun:
            raise exceptions.NotImplementedError
        return self.runfun([self.binary,
                            '-d', '%d' % self.digits,
                            '-c', '%d' % self.counter,
                            '%02d' % self.key]).strip()

def main():
    DB_DUMP_FN = 't_otp.kdb.dump'       # kdb5_util dump
    STASH_FN = 't_otp.kstash'           # kdb5_util add_mkey -s
    global YKCLIENT_PORT, YKCLIENT_HOST

    def prime_db(realm, fname):
        # We should rather load with `-update -ov' (using the
        # "ovsec_adm_export") but dump doesn't seem to work with `-ov'
        # AFAICT.
        global kdb5_util
        realm.run_as_master([kdb5_util, 'load', fname])
        fn = realm._kdc_conf['master']['realms']['$realm']['key_stash_file']
        fn = fn.replace('$testdir', realm.testdir).replace('$type', 'master')
        os.system('cp %s %s' % (STASH_FN, fn))

    # Create db and start KDC.
    realm = K5Realm(realm='KRB-OTP.NORDU.NET',
                    krb5_conf=otp_krb5_conf,
                    start_kdc=False,
                    create_user=False)
    # Load kdb from a dump file and copy the stash file in place.
    prime_db(realm, DB_DUMP_FN)
    # Start KDC.
    realm.start_kdc()

    # TODO: Set up the yubiserve db.
    if False:                         
        # /u/src/yubico-yubiserve-3.1.zip contains weird dbconf.py so I did
        # sed -i 's/\?  /    /g' dbconf.py
        # Create an OATH token in database with nickname 'm1'
        os.system('FIXME/yubiserve/dbconf.py -ha m1 token:m1 00')

        # Add an API key for 'm2'
        """
        42:yubiserve% ./dbconf.py -aa m2
        New API Key for 'm2': 'aWx2R29yRGxzMEtBajBXT05yR2U='
        Your API Key ID is: 1
        """

        # Start a yubiserve.  Note that stdout has to be flushed in
        # yubiserve.py after the sentinel has been printed or we'll
        # hang in _start_daemon() forever.
        _start_daemon(['/home/linus/p/krb-otp/yubiserve/yubiserve.py'],
                      _build_env(), 'HTTP Server is running.')

    # Start an http server for testing the ykclient method.
    cmd = ['../util/http-server.py', '-f', 't_otp.http_ykclient',
           YKCLIENT_HOST, str(YKCLIENT_PORT)]
    _start_daemon(cmd, _build_env(), 'http-server.py running')

    # Start an http server for testing the basicauth method.
    # FIXME.
    
    # Get a ticket for use as FAST armor.
    realm.kinit('linus@%s' % realm.realm, password='kaka')
    realm.klist('linus@%s' % realm.realm)

    # Calculate an OTP and get a ticket for otp@.
    t = OathToken(runfun=realm.run_as_client)
    otp = t.next_otp()
    realm.kinit('m1@%s' % realm.realm, flags=['-T', realm.ccache,
                                              '-X', 'OTP=%s' % otp])
    realm.klist('m1@%s' % realm.realm)

    # Expect failure.
    realm.kinit('m1@%s' % realm.realm,
                flags=['-T', realm.ccache, '-X', 'OTP=%s' % otp],
                expected_code=1)

    # Stop KDC.
    realm.stop()

if __name__ == '__main__':
    main()
