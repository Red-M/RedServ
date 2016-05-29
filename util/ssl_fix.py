# RedServ
# Copyright (C) 2016  Red_M ( http://bitbucket.com/Red_M )

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

import ssl
import sys
import os
import sys
import subprocess
from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter
if sys.version_info < (3, 0):
    from cherrypy.wsgiserver.ssl_pyopenssl import pyOpenSSLAdapter
else:
    from util.ssl_pyopenssl import pyOpenSSLAdapter

from cherrypy import wsgiserver

os.chdir('.' or sys.path[0])
current_dir = os.path.join(os.getcwd(),os.sep.join(sys.argv[0].split(os.sep)[0:-1]))
if current_dir.endswith("."):
    current_dir = current_dir[0:-1]

try:
  import OpenSSL
except ImportError:
  pass

def fix(ssl_adapters,RedServ):
    ciphers = (
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-CHACHA20-POLY1305',
    'EECDH+AESGCM',
    'EDH+AESGCM',
    'AES256+EECDH',
    'AES256+EDH',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'DHE-RSA-AES128-GCM-SHA256',
    'DHE-DSS-AES128-GCM-SHA256',
    'kEDH+AESGCM',
    'ECDHE-RSA-AES128-SHA256',
    'ECDHE-ECDSA-AES128-SHA256',
    'ECDHE-RSA-AES128-SHA',
    'ECDHE-ECDSA-AES128-SHA',
    'ECDHE-RSA-AES256-SHA384',
    'ECDHE-RSA-AES256-SHA',
    'ECDH+AESGCM',
    'DH+AESGCM:ECDH+AES256',
    'DH+AES256',
    'ECDH+AES128',
    'DH+AES',
    'ECDHE+HIGH',
    'ECDH+HIGH',
    'DH+HIGH',
    'RSA+HIGH',
    '!aNULL',
    '!eNULL',
    '!LOW',
    '!EXPORT',
    '!MD5',
    '!DSS',
    '!CBC',
    '!3DES',
    '!DES',
    '!RC4',
    '!SSLv2',
    '!PSK',
    '!aECDH',
    '!EDH-DSS-DES-CBC3-SHA',
    '!EDH-RSA-DES-CBC3-SHA',
    '!KRB5-DES-CBC3-SHA'
    )

    class BuiltinSsl(BuiltinSSLAdapter):
        '''Vulnerable, on py2 < 2.7.9, py3 < 3.3:
        * POODLE (SSLv3), adding ``!SSLv3`` to cipher list makes it very incompatible
        * can't disable TLS compression (CRIME)
        * supports Secure Client-Initiated Renegotiation (DOS)
        * no Forward Secrecy
        Also session caching doesn't work. Some tweaks are posslbe, but don't really
        change much. For example, it's possible to use ssl.PROTOCOL_TLSv1 instead of
        ssl.PROTOCOL_SSLv23 with little worse compatiblity.
        '''
        def __init__(self, certificate, private_key, certificate_chain=None):
            super().__init__(certificate, private_key, certificate_chain)
            self.dh_key_file_loc = os.path.join(current_dir,'util','tmp_dh_file')
            if not os.path.exists(self.dh_key_file_loc):
                print("INFO: Generating DH key for HTTPS. Please wait.")
                p = subprocess.call(["openssl","dhparam","-outform","PEM","-out",self.dh_key_file_loc,"2048"], stderr=subprocess.PIPE)
                print("INFO: HTTPS DH key generated at: "+self.dh_key_file_loc)
            
        def bind(self, sock):
            sock = super().bind(sock)
            """Wrap and return the given socket."""
            #print(str(dir(self)))
            return sock

        def wrap(self, sock):
            """Wrap and return the given socket, plus WSGI environ entries."""
            #print(dir(self))

            def pick_certificate(sock,hostname_recieved,context):
                #print(str(dir(context)))
                #print(str(sock.cipher()))
                config = RedServ.get_config()
                key = None
                cert = None
                if not hostname_recieved==None:
                    hostname_recieved = hostname_recieved
                else:
                    hostname_recieved = "default"

                def certloader(config_data,hostname):
                    key = config_data[hostname]['key']
                    cert = config_data[hostname]['cert']
                    if 'ca_chain' in config_data[hostname]:
                        ca_chain = config_data[hostname]['ca_chain']
                    else:
                        ca_chain = None
                    return(key,cert,ca_chain)

                try:
                    if 'certificates' in config['HTTPS']:
                        if hostname_recieved in config['HTTPS']['certificates']:
                            (key,cert,ca_chain) = certloader(config['HTTPS']['certificates'],hostname_recieved)
                        else:
                            if 'wildcard-certificates' in config['HTTPS']:
                                for cert_chain in config['HTTPS']['wildcard-certificates']:
                                    if cert_chain.startswith("*"):
                                        if hostname_recieved.endswith(cert_chain[1:]):
                                            (key,cert,ca_chain) = certloader(config['HTTPS']['wildcard-certificates'],cert_chain)
                                    if cert_chain.endswith("*"):
                                        if hostname_recieved.startswith(cert_chain[:-1]):
                                            (key,cert,ca_chain) = certloader(config['HTTPS']['wildcard-certificates'],cert_chain)
                            else:
                                (key,cert,ca_chain) = certloader(config['HTTPS']['certificates'],'default')
                except KeyError:
                    pass
                if not (key==None and cert==None):
                    if not ca_chain==None:
                        ca_chain = os.path.join(current_dir,ca_chain)
                    #os.path.join(current_dir,key),ca_chain,os.path.join(current_dir,cert)
                    c = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                    c.options |= ssl.OP_NO_SSLv2
                    c.options |= ssl.OP_NO_SSLv3
                    c.options |= ssl.OP_NO_COMPRESSION
                    c.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
                    c.options |= ssl.OP_SINGLE_DH_USE
                    c.options |= ssl.OP_SINGLE_ECDH_USE
                    c.load_dh_params(self.dh_key_file_loc)
                    c.set_ecdh_curve('prime256v1')
                    c.set_servername_callback(pick_certificate)
                    c.set_ciphers(':'.join(ciphers)+':@STRENGTH')
                    if not ca_chain==None:
                        c.load_verify_locations(capath=ca_chain)
                    c.load_cert_chain(os.path.join(current_dir,cert),os.path.join(current_dir,key))
                    sock.context = c
                    #nc = create_ssl_context(os.path.join(current_dir,'util','tmp_dh_file'),':'.join(ciphers),os.path.join(current_dir,key),ca_chain,os.path.join(current_dir,cert))
                    # if connection.total_renegotiations()>3:
                        # connection.shutdown()
                        # connection.close()
                        # RedServ.debugger(3,"Nuked an SSL conn. Too many renegotiations.")
                    # if not hostname_recieved==None:
                        # connection.set_tlsext_host_name(hostname_recieved.encode('utf-8'))
                    # connection.set_context(nc)
                    return(None)
            
            
            
            config = RedServ.get_config()
            c = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            c.options |= ssl.OP_NO_SSLv2
            c.options |= ssl.OP_NO_SSLv3
            c.options |= ssl.OP_NO_COMPRESSION
            c.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
            c.options |= ssl.OP_SINGLE_DH_USE
            c.options |= ssl.OP_SINGLE_ECDH_USE
            c.load_dh_params(self.dh_key_file_loc)
            c.set_ecdh_curve('prime256v1')
            c.set_servername_callback(pick_certificate)
            c.set_ciphers(':'.join(ciphers)+':@STRENGTH')
            c.load_verify_locations(capath=os.path.join(current_dir,config["HTTPS"]["CA_cert"]))
            c.load_cert_chain(config["HTTPS"]["cert"], config["HTTPS"]["cert_private_key"])
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







    class Pyopenssl(pyOpenSSLAdapter):
      '''Mostly fine, except:
        * Secure Client-Initiated Renegotiation
        * no Forward Secrecy, SSL.OP_SINGLE_DH_USE could have helped but it didn't
        * FS is now enabled. It simply required load_tmp_dh.
      '''

    def get_context(self):
        """Return an SSL.Context from self attributes."""
        
        def npn_callback(connection):
            if connection.total_renegotiations()>3:
                connection.shutdown()
                connection.close()
                RedServ.debugger(3,"Nuked an SSL conn. Too many renegotiations.")
            if not connection.get_servername()==None:
                connection.set_tlsext_host_name(connection.get_servername().encode('utf-8'))
            return([b'http/1.0'])
        
        def create_ssl_context(dhparams,ciphers,privkey,ca_chain,cert):
            c = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
            c.set_options(OpenSSL.SSL.OP_NO_COMPRESSION | OpenSSL.SSL.OP_SINGLE_DH_USE | OpenSSL.SSL.OP_CIPHER_SERVER_PREFERENCE | OpenSSL.SSL.OP_NO_SSLv2 | OpenSSL.SSL.OP_NO_SSLv3)
            c.load_tmp_dh(dhparams)
            c.set_tmp_ecdh(OpenSSL.crypto.get_elliptic_curve('prime256v1'))
            c.set_cipher_list(ciphers+':@STRENGTH')
            c.use_privatekey_file(privkey)
            if not ca_chain==None:
                c.load_verify_locations(ca_chain)
            c.use_certificate_file(cert)
            c.set_npn_advertise_callback(npn_callback)
            return(c)
        
        def pick_certificate(connection):
            config = RedServ.get_config()
            key = None
            cert = None
            if not connection.get_servername()==None:
                hostname_recieved = connection.get_servername()
            else:
                hostname_recieved = "default"

            def certloader(config_data,hostname):
                key = config_data[hostname]['key']
                cert = config_data[hostname]['cert']
                if 'ca_chain' in config_data[hostname]:
                    ca_chain = config_data[hostname]['ca_chain']
                else:
                    ca_chain = None
                return(key,cert,ca_chain)

            try:
                if 'certificates' in config['HTTPS']:
                    if hostname_recieved in config['HTTPS']['certificates']:
                        (key,cert,ca_chain) = certloader(config['HTTPS']['certificates'],hostname_recieved)
                    else:
                        if 'wildcard-certificates' in config['HTTPS']:
                            for cert_chain in config['HTTPS']['wildcard-certificates']:
                                if cert_chain.startswith("*"):
                                    if hostname_recieved.endswith(cert_chain[1:]):
                                        (key,cert,ca_chain) = certloader(config['HTTPS']['wildcard-certificates'],cert_chain)
                                if cert_chain.endswith("*"):
                                    if hostname_recieved.startswith(cert_chain[:-1]):
                                        (key,cert,ca_chain) = certloader(config['HTTPS']['wildcard-certificates'],cert_chain)
                        else:
                            (key,cert,ca_chain) = certloader(config['HTTPS']['certificates'],'default')
            except KeyError:
                pass
            if not (key==None and cert==None):
                if not ca_chain==None:
                    ca_chain = os.path.join(current_dir,ca_chain)
                nc = create_ssl_context(os.path.join(current_dir,'util','tmp_dh_file'),':'.join(ciphers),os.path.join(current_dir,key),ca_chain,os.path.join(current_dir,cert))
                if connection.total_renegotiations()>3:
                    connection.shutdown()
                    connection.close()
                    RedServ.debugger(3,"Nuked an SSL conn. Too many renegotiations.")
                if not hostname_recieved==None:
                    connection.set_tlsext_host_name(hostname_recieved.encode('utf-8'))
                connection.set_context(nc)
        
        dh_key_file_loc = os.path.join(current_dir,'util','tmp_dh_file')
        if not os.path.exists(dh_key_file_loc):
            print("INFO: Generating DH key for HTTPS. Please wait.")
            p = subprocess.call(["openssl","dhparam","-out",dh_key_file_loc,"2048"], stderr=subprocess.PIPE)
            print("INFO: HTTPS DH key generated at: "+dh_key_file_loc)
        if not self.certificate_chain:
            self.certificate_chain = None
        c = create_ssl_context(dh_key_file_loc,':'.join(ciphers),self.private_key,self.certificate_chain,self.certificate)
        c.set_tlsext_servername_callback(pick_certificate)
        return c

    ssl_adapters['custom-pyopenssl'] = Pyopenssl
    return(ssl_adapters)