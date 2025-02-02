# RedServ
# Copyright (C) 2019  Red_M ( http://bitbucket.com/Red_M )

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# This section of code is to correct SSL issues with Cherrypy until they correct them.
# This section will be removed later.
# Author of original code: http://recollection.saaj.me/article/cherrypy-questions-testing-ssl-and-docker.html#experiment
# Some suggestions from: https://github.com/ran-sama/python3_https_tls1_2_microserver/blob/master/server.py

import ssl
import sys
import os
import sys
import subprocess

from cheroot.ssl.pyopenssl import pyOpenSSLAdapter
from cheroot.ssl.builtin import BuiltinSSLAdapter

try:
    from cherrypy import wsgiserver
except Exception as e:
    import cheroot as wsgiserver

os.chdir('.' or sys.path[0])
current_dir = os.path.join(os.getcwd(),os.sep.join(sys.argv[0].split(os.sep)[0:-1]))
if current_dir.endswith("."):
    current_dir = current_dir[0:-1]

try:
  import OpenSSL
except ImportError:
  pass

def fix(ssl_adapters,RedServ):
    __ssl_patch_version__ = '1.2.2'
    RedServ.debugger(3,'Loaded RedServ SSL patch version: '+__ssl_patch_version__)
    default_ciphers = (
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-ECDSA-CHACHA20-POLY1305'
    )

    builtin_ssl_ops = [
        ssl.OP_NO_SSLv2,
        ssl.OP_NO_SSLv3,
        ssl.OP_NO_TLSv1,
        ssl.OP_NO_TLSv1_1,
        ssl.OP_NO_COMPRESSION,
        ssl.OP_SINGLE_DH_USE,
        ssl.OP_SINGLE_ECDH_USE,
        ssl.OP_CIPHER_SERVER_PREFERENCE
    ]

    pyopenssl_ssl_ops = [
        OpenSSL.SSL.OP_NO_COMPRESSION,
        OpenSSL.SSL.OP_SINGLE_DH_USE,
        OpenSSL.SSL.OP_SINGLE_ECDH_USE,
        OpenSSL.SSL.OP_CIPHER_SERVER_PREFERENCE,
        OpenSSL.SSL.OP_NO_SSLv2,
        OpenSSL.SSL.OP_NO_SSLv3,
        OpenSSL.SSL.OP_NO_TLSv1,
        OpenSSL.SSL.OP_NO_TLSv1_1
    ]

    config = RedServ.get_config()
    if not "ciphers" in config["HTTPS"]:
        ciphers = ':'.join(default_ciphers)
    else:
        ciphers = config["HTTPS"]["ciphers"]

    class BuiltinSsl(BuiltinSSLAdapter):
        '''Vulnerable, on py2 < 2.7.9, py3 < 3.3:
        * supports Secure Client-Initiated Renegotiation (DOS)
        Also session caching doesn't work (not sure about this). Some tweaks are posslbe, but don't really
        change much.
        '''
        def __init__(self, certificate, private_key, certificate_chain=None, ssl_ciphers=None):
            super().__init__(certificate, private_key, certificate_chain)
            self.dh_key_file_loc = os.path.join(current_dir,'util','tmp_dh_file')
            if not os.path.exists(self.dh_key_file_loc):
                print("INFO: Generating DH key for HTTPS. Please wait.")
                p = subprocess.call(["openssl","dhparam","-outform","PEM","-out",self.dh_key_file_loc,"2048"], stderr=subprocess.PIPE)
                print("INFO: HTTPS DH key generated at: "+self.dh_key_file_loc)

        # def bind(self, sock):
            # sock = super().bind(sock)
            # """Wrap and return the given socket."""
            # return sock

        def wrap(self, sock):
            """Wrap and return the given socket, plus WSGI environ entries."""
            # print(dir(self))
            def pick_certificate(sock,hostname_recieved,context):
                #print(str(dir(context)))
                #print(str(sock.cipher()))
                config = RedServ.get_config()
                if not "ciphers" in config["HTTPS"]:
                    generic_ciphers = ':'.join(default_ciphers)
                else:
                    generic_ciphers = config["HTTPS"]["ciphers"]
                key = None
                cert = None
                if not hostname_recieved==None:
                    hostname_recieved = hostname_recieved
                else:
                    hostname_recieved = "default"

                # print(hostname_recieved)

                try:
                    if 'certificates' in config['HTTPS']:
                        if hostname_recieved in config['HTTPS']['certificates']:
                            (key,cert,ca_chain,ciphers) = RedServ.certloader(config['HTTPS']['certificates'],hostname_recieved)
                        else:
                            if 'wildcard-certificates' in config['HTTPS']:
                                for cert_chain in config['HTTPS']['wildcard-certificates']:
                                    if cert_chain.startswith("*"):
                                        if hostname_recieved.endswith(cert_chain[1:]):
                                            (key,cert,ca_chain,ciphers) = RedServ.certloader(config['HTTPS']['wildcard-certificates'],cert_chain)
                                    if cert_chain.endswith("*"):
                                        if hostname_recieved.startswith(cert_chain[:-1]):
                                            (key,cert,ca_chain,ciphers) = RedServ.certloader(config['HTTPS']['wildcard-certificates'],cert_chain)
                            else:
                                (key,cert,ca_chain,ciphers) = RedServ.certloader(config['HTTPS']['certificates'],'default')
                except KeyError:
                    pass
                if not (key==None and cert==None):
                    if not ca_chain==None:
                        ca_chain = os.path.join(current_dir,ca_chain)
                    #os.path.join(current_dir,key),ca_chain,os.path.join(current_dir,cert)
                    # c = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                    c = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
                    for op in builtin_ssl_ops:
                        c.options |= op
                    c.load_dh_params(self.dh_key_file_loc)
                    c.set_ecdh_curve('secp384r1')
                    if ciphers==None:
                        ciphers = generic_ciphers
                    c.set_ciphers(ciphers+':@STRENGTH')
                    #c.set_npn_protocols(['http/1.1','http/1.0'])
                    if isinstance(cert,type([])):
                        i = 0
                        for certs in cert:
                            if not ca_chain[i]==None:
                                c.load_verify_locations(capath=ca_chain[i])
                            c.load_cert_chain(os.path.join(current_dir,cert[i]),os.path.join(current_dir,key[i]))
                            i+=1
                    else:
                        if not ca_chain==None:
                            c.load_verify_locations(capath=ca_chain)
                        c.load_cert_chain(os.path.join(current_dir,cert),os.path.join(current_dir,key))
                    sock.context = c
                return(None)



            config = RedServ.get_config()
            if not "ciphers" in config["HTTPS"]:
                generic_ciphers = ':'.join(default_ciphers)
            else:
                generic_ciphers = config["HTTPS"]["ciphers"]
            # c = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            c = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            c.set_servername_callback(pick_certificate)
            for op in builtin_ssl_ops:
                c.options |= op
            c.load_dh_params(self.dh_key_file_loc)
            c.set_ecdh_curve('secp384r1')
            (key,cert,ca_chain,ciphers) = RedServ.certloader(config['HTTPS']['certificates'],'default')
            if ciphers==None:
                ciphers = generic_ciphers
            c.set_ciphers(ciphers+':@STRENGTH')
            c.load_verify_locations(capath=os.path.join(current_dir,config["HTTPS"]["CA_cert"]))
            # c.set_alpn_protocols(['http/1.1','http/1.0'])
            # c.set_npn_protocols(['http/1.1','http/1.0']) # needs newer SSL
            if isinstance(cert,type([])):
                i = 0
                for certs in cert:
                    if not ca_chain[i]==None:
                        c.load_verify_locations(capath=ca_chain[i])
                    c.load_cert_chain(os.path.join(current_dir,cert[i]),os.path.join(current_dir,key[i]))
                    i+=1
            else:
                if not ca_chain==None:
                    c.load_verify_locations(capath=ca_chain)
                c.load_cert_chain(os.path.join(current_dir,cert),os.path.join(current_dir,key))
            try:
                s = c.wrap_socket(sock,do_handshake_on_connect=True,server_side=True)
            except ssl.SSLError:
                e = sys.exc_info()[1]
                if e.errno == ssl.SSL_ERROR_EOF:
                    # This is almost certainly due to the cherrypy engine
                    # 'pinging' the socket to assert it's connectable;
                    # the 'ping' isn't SSL.
                    return None, {}
                elif e.errno == ssl.SSL_ERROR_SSL:
                    if e.args[1].endswith('http request'):
                        # The client is speaking HTTP to an HTTPS server.
                        raise wsgiserver.NoSSLError
                elif e.args[1].endswith('unknown protocol'):
                    # The client is speaking some non-HTTP protocol.
                    # Drop the conn.
                    return None, {}
                raise

            return s, self.get_environ(s)

    ssl_adapters['custom-ssl'] = BuiltinSsl







    # if sys.version_info < (3, 0):
    class Pyopenssl(pyOpenSSLAdapter):
        '''Mostly fine, except:
            * Secure Client-Initiated Renegotiation
            * no Forward Secrecy, SSL.OP_SINGLE_DH_USE could have helped but it didn't
            * FS is now enabled. It simply required load_tmp_dh.
        '''

        def get_context(self):
            """Return an SSL.Context from self attributes."""

            config = RedServ.get_config()
            ciphers = None

            def alpn_callback(conn, options):
                supported_protocols = [b'http/1.1',b'http/1.0']
                for proto in supported_protocols:
                    if proto in options:
                        return(proto)

            def npn_callback(connection):
                if connection.total_renegotiations()>3:
                    connection.shutdown()
                    connection.close()
                    RedServ.debugger(3,"Nuked an SSL conn. Too many renegotiations.")
                if not connection.get_servername()==None:
                    connection.set_tlsext_host_name(connection.get_servername())
                return([b'http/1.1',b'http/1.0'])

            def create_ssl_context(dhparams,ciphers,privkey,ca_chain,cert):
                config = RedServ.get_config()
                c = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
                options = 0
                for sel_option in pyopenssl_ssl_ops:
                    options = options | sel_option
                c.set_options(options)
                c.load_tmp_dh(dhparams)
                c.set_tmp_ecdh(OpenSSL.crypto.get_elliptic_curve('secp384r1'))
                if ciphers==None:
                    if "ciphers" in config["HTTPS"]:
                        ciphers = config["HTTPS"]["ciphers"]
                    else:
                        ciphers = ':'.join(default_ciphers)
                if not '@STRENGTH' in ciphers:
                    ciphers = ciphers+':@STRENGTH'
                c.set_cipher_list(ciphers)
                c.use_privatekey_file(privkey)
                if not ca_chain==None:
                    c.load_verify_locations(ca_chain)
                c.use_certificate_file(cert)
                #c.set_npn_advertise_callback(npn_callback)
                #c.set_alpn_select_callback(alpn_callback)
                return(c)

            def pick_certificate(connection):
                config = RedServ.get_config()
                key = None
                cert = None
                ciphers = None
                if not connection.get_servername()==None:
                    hostname_recieved = connection.get_servername()
                else:
                    hostname_recieved = "default"

                try:
                    if 'certificates' in config['HTTPS']:
                        if hostname_recieved in config['HTTPS']['certificates']:
                            (key,cert,ca_chain,ciphers) = RedServ.certloader(config['HTTPS']['certificates'],hostname_recieved)
                        else:
                            if 'wildcard-certificates' in config['HTTPS']:
                                for cert_chain in config['HTTPS']['wildcard-certificates']:
                                    cert_chain = cert_chain.encode('utf8')
                                    if cert_chain.startswith(b'*'):
                                        if hostname_recieved.endswith(cert_chain[1:]):
                                            (key,cert,ca_chain,ciphers) = RedServ.certloader(config['HTTPS']['wildcard-certificates'],cert_chain)
                                    if cert_chain.endswith(b'*'):
                                        if hostname_recieved.startswith(cert_chain[:-1]):
                                            (key,cert,ca_chain,ciphers) = RedServ.certloader(config['HTTPS']['wildcard-certificates'],cert_chain)
                            else:
                                (key,cert,ca_chain,ciphers) = RedServ.certloader(config['HTTPS']['certificates'],'default')
                except KeyError:
                    pass
                if not (key==None and cert==None):
                    if not ca_chain==None:
                        ca_chain = os.path.join(current_dir,ca_chain)

                    nc = create_ssl_context(os.path.join(current_dir,'util','tmp_dh_file'),ciphers,os.path.join(current_dir,key),ca_chain,os.path.join(current_dir,cert))
                    if connection.total_renegotiations()>3:
                        connection.shutdown()
                        connection.close()
                        RedServ.debugger(3,"Nuked an SSL conn. Too many renegotiations.")
                    connection.set_context(nc)

            dh_key_file_loc = os.path.join(current_dir,'util','tmp_dh_file')
            if not os.path.exists(dh_key_file_loc):
                print("INFO: Generating DH key for HTTPS. Please wait.")
                p = subprocess.call(["openssl","dhparam","-out",dh_key_file_loc,"2048"], stderr=subprocess.PIPE)
                print("INFO: HTTPS DH key generated at: "+dh_key_file_loc)
            if 'default' in config['HTTPS']['certificates']:
                (self.private_key,self.certificate,self.certificate_chain,ciphers) = RedServ.certloader(config['HTTPS']['certificates'],'default')
            if not self.certificate_chain:
                self.certificate_chain = None



            c = create_ssl_context(dh_key_file_loc,ciphers,self.private_key,self.certificate_chain,self.certificate)
            c.set_tlsext_servername_callback(pick_certificate)
            self.context = c
            return c

    ssl_adapters['custom-pyopenssl'] = Pyopenssl
    return(ssl_adapters)
