# This section of code is to correct SSL issues with Cherrypy until they correct them.
# This section will be removed later.
# Author of original code: http://recollection.saaj.me/article/cherrypy-questions-testing-ssl-and-docker.html#experiment

import ssl
import sys
import os
import sys
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

def fix(ssl_adapters):
    ciphers = (
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


    class Pyopenssl(pyOpenSSLAdapter):
      '''Mostly fine, except:
        * Secure Client-Initiated Renegotiation
        * no Forward Secrecy, SSL.OP_SINGLE_DH_USE could have helped but it didn't
      '''

      def get_context(self):
        """Return an SSL.Context from self attributes."""
        c = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)

        # override:
        c.set_options(OpenSSL.SSL.OP_NO_COMPRESSION | OpenSSL.SSL.OP_SINGLE_DH_USE | OpenSSL.SSL.OP_NO_SSLv2 | OpenSSL.SSL.OP_NO_SSLv3)
        c.load_tmp_dh(os.path.join(current_dir,'util','tmp_dh_file'))
        c.set_tmp_ecdh(OpenSSL.crypto.get_elliptic_curve('prime256v1'))
        c.set_cipher_list(':'.join(ciphers))

        c.use_privatekey_file(self.private_key)
        if self.certificate_chain:
            c.load_verify_locations(self.certificate_chain)
        c.use_certificate_file(self.certificate)
        return c

    ssl_adapters['custom-pyopenssl'] = Pyopenssl
    return(ssl_adapters)