# This section of code is to correct SSL issues with Cherrypy until they correct them.
# This section will be removed later.
# Author of original code: http://recollection.saaj.me/article/cherrypy-questions-testing-ssl-and-docker.html#experiment

import ssl
import sys
import os
import sys
import subprocess
from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter
from cherrypy.wsgiserver.ssl_pyopenssl import pyOpenSSLAdapter

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
    'ECDH+HIGH',
    'DH+HIGH',
    '!aNULL',
    '!eNULL',
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
    '!KRB5-DES-CBC3-SHA',
    '@STRENGTH'
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

      def wrap(self, sock):
        """Wrap and return the given socket, plus WSGI environ entries."""
        try:
          s = ssl.wrap_socket(
            sock,
            ciphers = ciphers, # the override is for this line
            do_handshake_on_connect = True,
            server_side = True,
            certfile = self.certificate,
            keyfile = self.private_key,
            ssl_version = ssl.PROTOCOL_SSLv23
          )
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

    def pick_certificate(connection):
        config = RedServ.get_config()
        key = None
        cert = None
        #print(connection.get_servername()+": "+str(connection.get_servername() in config['HTTPS']['certificates']))
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
                if connection.get_servername() in config['HTTPS']['certificates']:
                    (key,cert,ca_chain) = certloader(config['HTTPS']['certificates'],connection.get_servername())
                else:
                    if 'wildcard-certificates' in config['HTTPS']:
                        for cert_chain in config['HTTPS']['wildcard-certificates']:
                            if cert_chain.startswith("*"):
                                if connection.get_servername().endswith(cert_chain[1:]):
                                    (key,cert,ca_chain) = certloader(config['HTTPS']['wildcard-certificates'],cert_chain)
                            if cert_chain.endswith("*"):
                                if connection.get_servername().startswith(cert_chain[:-1]):
                                    (key,cert,ca_chain) = certloader(config['HTTPS']['wildcard-certificates'],cert_chain)
                    else:
                        (key,cert,ca_chain) = certloader(config['HTTPS']['certificates'],'default')
        except KeyError:
            pass
        if not (key==None and cert==None):
            nc = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
            nc.set_options(OpenSSL.SSL.OP_NO_COMPRESSION | OpenSSL.SSL.OP_SINGLE_DH_USE | OpenSSL.SSL.OP_NO_SSLv2 | OpenSSL.SSL.OP_NO_SSLv3)
            nc.load_tmp_dh(os.path.join(current_dir,'util','tmp_dh_file'))
            nc.set_tmp_ecdh(OpenSSL.crypto.get_elliptic_curve('prime256v1'))
            nc.set_cipher_list(':'.join(ciphers))
            nc.use_privatekey_file(os.path.join(current_dir,key))
            if not ca_chain==None:
                nc.load_verify_locations(os.path.join(current_dir,ca_chain))
            nc.use_certificate_file(os.path.join(current_dir,cert))
            connection.set_context(nc)

    class Pyopenssl(pyOpenSSLAdapter):
      '''Mostly fine, except:
        * Secure Client-Initiated Renegotiation
        * no Forward Secrecy, SSL.OP_SINGLE_DH_USE could have helped but it didn't
        * FS is now enabled. It simply required load_tmp_dh.
      '''

      def get_context(self):
        """Return an SSL.Context from self attributes."""
        c = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)

        # override:
        c.set_options(OpenSSL.SSL.OP_NO_COMPRESSION | OpenSSL.SSL.OP_SINGLE_DH_USE | OpenSSL.SSL.OP_NO_SSLv2 | OpenSSL.SSL.OP_NO_SSLv3)
        dh_key_file_loc = os.path.join(current_dir,'util','tmp_dh_file')
        if not os.path.exists(dh_key_file_loc):
            print("INFO: Generating DH key for HTTPS. Please wait.")
            p = subprocess.call(["openssl","dhparam","-out",dh_key_file_loc,"2048"], stderr=subprocess.PIPE)
            print("INFO: HTTPS DH key generated at: "+dh_key_file_loc)
        c.load_tmp_dh(os.path.join(current_dir,'util','tmp_dh_file'))
        c.set_tmp_ecdh(OpenSSL.crypto.get_elliptic_curve('prime256v1'))
        c.set_cipher_list(':'.join(ciphers))

        c.use_privatekey_file(self.private_key)
        if self.certificate_chain:
            c.load_verify_locations(self.certificate_chain)
        c.use_certificate_file(self.certificate)
        c.set_tlsext_servername_callback(pick_certificate)
        return c

    ssl_adapters['custom-pyopenssl'] = Pyopenssl
    return(ssl_adapters)