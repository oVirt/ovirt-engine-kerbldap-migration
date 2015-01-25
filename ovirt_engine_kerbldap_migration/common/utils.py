import base64
import datetime
import glob
import logging
import os
import shutil
import subprocess
import sys
import tempfile


from M2Crypto import RSA


try:
    import dns.resolver
except ImportError:
    raise RuntimeError('Please install python-dns')

try:
    import psycopg2
except ImportError:
    raise RuntimeError('Please install python-psycopg2')


class Base(object):
    LOG_PREFIX = 'converter'

    @property
    def logger(self):
        return self._logger

    def __init__(self):
        self._logger = logging.getLogger(
            '%s.%s' % (
                self.LOG_PREFIX,
                self.__class__.__name__,
            )
        )


class Statement(Base):

    _connection = None

    def __init__(self):
        super(Statement, self).__init__()

    def connect(
        self,
        host=None,
        port=None,
        secured=False,
        securedHostValidation=True,
        user=None,
        password=None,
        database=None,
    ):
        sslmode = 'allow'
        if secured:
            if securedHostValidation:
                sslmode = 'verify-full'
            else:
                sslmode = 'require'

        self.logger.debug(
            (
                'entry host=%s, port=%s, secured=%s, '
                'securedHostValidation=%s, user=%s, database=%s'
            ),
            host,
            port,
            secured,
            securedHostValidation,
            user,
            database,
        )

        #
        # old psycopg2 does not know how to ignore
        # uselss parameters
        #
        if not host:
            connection = psycopg2.connect(
                database=database,
            )
        else:
            #
            # port cast is required as old psycopg2
            # does not support unicode strings for port.
            # do not cast to int to avoid breaking usock.
            #
            connection = psycopg2.connect(
                host=host,
                port=str(port),
                user=user,
                password=password,
                database=database,
                sslmode=sslmode,
            )

        self._connection = connection

    def execute(
        self,
        statement,
        args=dict(),
    ):
        self.logger.debug('entry statement=%s %s', statement, args)

        ret = []
        cursor = None
        try:
            cursor = self._connection.cursor()
            cursor.execute(
                statement,
                args,
            )
            if cursor.description is not None:
                cols = [d[0] for d in cursor.description]
                while True:
                    entry = cursor.fetchone()
                    if entry is None:
                        break
                    ret.append(dict(zip(cols, entry)))
        finally:
            if cursor is not None:
                cursor.close()

        return ret

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.logger.debug('Commit')
            self._connection.commit()
        else:
            self.logger.debug('Rollback')
            self._connection.rollback()
        self._connection.close()


class OptionDecrypt(Base):

    def __init__(self, prefix='/'):
        super(OptionDecrypt, self).__init__()
        pkcs12 = os.path.join(prefix, 'etc/pki/ovirt-engine/keys/engine.p12')
        password = 'mypass'
        p = subprocess.Popen(
            [
                'openssl',
                'pkcs12',
                '-nocerts', '-nodes',
                '-in', pkcs12,
                '-passin', 'pass:%s' % password,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = p.communicate()

        if p.wait() != 0:
            self.logger.debug('openssl stderr: %s', stderr)
            raise RuntimeError('Failed to execute openssl')

        self._rsa = RSA.load_key_string(stdout)

    def decrypt(self, s):
        return self._rsa.private_decrypt(
            base64.b64decode(s),
            padding=RSA.pkcs1_padding,
        )


class VdcOptions(object):

    def __init__(self, statement):
        self._statement = statement

    def _getOptionForDomain(self, domain, name):
        ret = None

        result = self._statement.execute(
            statement="""
                select option_value
                from vdc_options
                where option_name = %(name)s
            """,
            args=dict(
                name=name,
            ),
        )
        if result:
            result = result[0]['option_value']
            for val in result.split(','):
                if val.startswith(domain + ':'):
                    ret = val.split(':', 1)[1]
                    break

        return ret

    def getDomainEntry(self, domain):
        provider = self._getOptionForDomain(domain, 'LDAPProviderTypes')
        ldapServers = self._getOptionForDomain(domain, 'LdapServers')
        if provider == 'activeDirectory':
            provider = 'ad'

        return dict(
            user=self._getOptionForDomain(domain, 'AdUserName'),
            password=self._getOptionForDomain(domain, 'AdUserPassword'),
            provider=provider.lower() if provider else None,
            ldapServers=ldapServers.split(',') if ldapServers else None,
        )


class DNS(Base):

    def __init__(self):
        super(DNS, self).__init__()

    def resolveSRVRecord(self, domain, protocol, service):
        query = '_%s._%s.%s' % (service, protocol, domain)
        response = dns.resolver.query(query, 'SRV')
        self.logger.debug(
            "Query result for srvrecord '%s': %s",
            query,
            response.response,
        )
        if not response:
            raise RuntimeError("Cannot resolve domain '%s'" % domain)

        ret = [
            entry.target.to_text() for entry in sorted(
                response,
                key=lambda e: e.priority,
                reverse=True,
            )
        ]
        self.logger.debug('Return: %s', ret)
        return ret


class Kerberos(Base):

    def __init__(self, prefix):
        super(Kerberos, self).__init__()
        self._prefix = prefix
        self._cache = None
        self._env = None

    def kinit(self, user, password):
        self.logger.debug('kinit')

        fd, self._cache = tempfile.mkstemp()
        os.close(fd)
        self._env = os.environ.get('KRB5CCNAME')
        os.environ['KRB5CCNAME'] = 'FILE:%s' % self._cache

        env = os.environ.copy()
        env['KRB5_CONFIG'] = os.path.join(
            self._prefix,
            'etc/ovirt-engine/krb5.conf',
        )
        p = subprocess.Popen(
            [
                'kinit',
                user,
            ],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = p.communicate(input=password)
        self.logger.debug('kinit stdout=%s, stderr=%s', stdout, stderr)
        if p.wait() != 0:
            raise RuntimeError(
                'Cannot authenticate to kerberos for account %s' % user
            )

    def kdestroy(self):
        self.logger.debug('kdestroy')
        try:
            p = subprocess.Popen(['kdestroy'])
            if p.wait() != 0:
                raise RuntimeError('Failed to execute kdestroy')
        finally:
            if self._env is None:
                del os.environ['KRB5CCNAME']
            else:
                os.environ['KRB5CCNAME'] = self._env
            if self._cache is not None:
                if os.path.exists(self._cache):
                    os.unlink(self._cache)
                self._cache = None


class Engine(Base):

    @property
    def prefix(self):
        return self._prefix

    @property
    def dataDir(self):
        return self._dataDir

    def __init__(self, prefix='/'):
        super(Engine, self).__init__()
        self._prefix = prefix
        if prefix == '/':
            self._dataDir = os.path.join(
                prefix,
                'usr',
                'share',
                'ovirt-engine',
            )
        else:
            self._dataDir = os.path.join(
                prefix,
                'share',
                'ovirt-engine',
            )

    def setupEnvironment(self):
        if self._prefix != '/':
            sys.path.insert(
                0,
                glob.glob(
                    os.path.join(
                        self._prefix,
                        'usr',
                        'lib*',
                        'python*',
                        'site-packages',
                    )
                )[0]
            )

    def getStatement(self):
        from ovirt_engine import configfile
        engineConfig = configfile.ConfigFile(
            files=[
                os.path.join(
                    self.dataDir,
                    'services',
                    'ovirt-engine',
                    'ovirt-engine.conf',
                ),
                os.path.join(
                    self.prefix,
                    'etc',
                    'ovirt-engine',
                    'engine.conf',
                ),
            ],
        )

        statement = Statement()
        statement.connect(
            host=engineConfig.get('ENGINE_DB_HOST'),
            port=engineConfig.get('ENGINE_DB_PORT'),
            secured=engineConfig.getboolean('ENGINE_DB_SECURED'),
            securedHostValidation=engineConfig.getboolean(
                'ENGINE_DB_SECURED_VALIDATION'
            ),
            user=engineConfig.get('ENGINE_DB_USER'),
            password=engineConfig.get('ENGINE_DB_PASSWORD'),
            database=engineConfig.get('ENGINE_DB_DATABASE'),
        )

        return statement


def setupLogger(log=None, debug=False):
    logger = logging.getLogger(Base.LOG_PREFIX)
    logger.propagate = False
    logger.setLevel(logging.DEBUG)

    try:
        h = logging.StreamHandler()
        h.setLevel(logging.INFO)
        h.setFormatter(
            logging.Formatter(
                fmt=(
                    '[%(levelname)-7s] '
                    '%(message)s'
                ),
            ),
        )
        logger.addHandler(h)

        if log is not None:
            h = logging.StreamHandler(open(log, 'w'))
            h.setLevel(logging.DEBUG if debug else logging.INFO)
            h.setFormatter(
                logging.Formatter(
                    fmt=(
                        '%(asctime)-15s '
                        '[%(levelname)-7s] '
                        '%(name)s.%(funcName)s:%(lineno)d '
                        '%(message)s'
                    ),
                ),
            )
            logger.addHandler(h)
    except IOError:
        logging.warning('Cannot initialize logging', exc_info=True)


class FileTransaction(Base):

    _files = []

    def __init__(self):
        super(FileTransaction, self).__init__()

    def _copyFile(self, src, dest):
        shutil.copyfile(src, dest)
        shutil.copystat(src, dest)
        srcStat = os.stat(src)
        os.chown(
            dest,
            srcStat.st_uid,
            srcStat.st_gid
        )

    def getFileName(self, name, forceNew=False):
        if forceNew and os.path.exists(name):
            raise RuntimeError('File %s already exists' % name)

        if os.path.exists(name):
            self._copyFile(
                name,
                '%s.%s' % (
                    name,
                    datetime.datetime.now().strftime('%Y%m%d%H%M%S')
                )
            )

        fd, tmpname = tempfile.mkstemp(
            suffix='.tmp',
            prefix='%s.' % os.path.basename(name),
            dir=os.path.dirname(name),
        )
        os.close(fd)

        self.logger.debug("Temp name for '%s' is '%s'", name, tmpname)
        self._files.append((tmpname, name))

        return tmpname

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.logger.debug('Commit %s', self._files)
            for tmpname, name in self._files:
                if os.path.exists(tmpname):
                    os.rename(tmpname, name)
        else:
            self.logger.debug('Rollback')
            for tmpname, name in self._files:
                if os.path.exists(tmpname):
                    os.unlink(tmpname)


# vim: expandtab tabstop=4 shiftwidth=4
