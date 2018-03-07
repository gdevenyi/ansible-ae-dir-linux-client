#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Export SSH keys of users from their LDAP entries into a directory
configured to hold all authorized keys (see pattern for AuthorizedKeysFile)
"""

__version__ = '0.14.0'

#-----------------------------------------------------------------------
# Imports
#-----------------------------------------------------------------------

# from Python's standard lib
import sys
import socket
import re
import time
import os.path
import glob
import logging
import pwd

# from ldap0 package
import ldap0
import ldap0.sasl
import ldap0.cidict
import ldap0.ldapurl
from ldap0.ldapobject import ReconnectLDAPObject

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

# Pathname of syslog device to be used
LOG_DEVICE = '/dev/log'

# regex pattern of acceptable SSH authorized keys
# this is handy when enforcing some rules on key comments
SSH_KEY_REGEX = '^ssh-(rsa|dss) .+$'

# Permissions for stored authorized keys
AUTHORIZED_KEY_MODE = 0644

# Trace level for ldap0 logging
PYLDAP_TRACELEVEL = 0

# attribute containing valid remote host IP addresses used to generate the
# key option from="pattern-list" (set to None to disable it)
RHOST_ATTR = 'aeRemoteHost'

# Whether to optimize search with memberOf filter
USE_MEMBEROF = 1

# Minimum number of user SSH keys expected to be found
# script exits with error code 2 and won't delete keys if less LDAP
# results than this number were received
EXPECTED_KEYS_MINCOUNT = 1

# Base filter for searching entries with attribute 'sshPublicKey'
USER_ENTRY_BASE_FILTER_TMPL = '(&(objectClass=ldapPublicKey)(sshPublicKey=*)%s(|%s))'

# 1. LDAP filter part to use for searching for user entries
# 2. Time in seconds after which a password is no longer valid (password expiry)
# MUST match attribute 'pwdMaxAge' of appropriate password policy entry
# Set to None or 0 to omit pwdChangedTime filter part.
USER_ENTRY_FILTERS = (
    ('(&(objectClass=aeUser)%s)', 6048000),
    ('(objectClass=aeService)%s', None),
)

# Path name of file containing all user names to ignore
USER_EXCLUDE_FILENAME = '/etc/ssh/ignore-ssh-keyfiles'

# Timeout in seconds when connecting to local and remote LDAP servers
# used for ldap0.OPT_NETWORK_TIMEOUT and ldap0.OPT_TIMEOUT
LDAP_TIMEOUT = 5.0

# Number of times connecting to LDAP is tried
LDAP_MAXRETRYCOUNT = 4

#CATCH_ALL_EXCEPTION = None
CATCH_ALL_EXCEPTION = Exception

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------


class LogWrapperFile(object):
    """
    file-like wrapper object around logging handler
    """

    def __init__(self, logger, log_level):
        self._logger = logger
        self._log_level = log_level

    def write(self, msg):
        """
        Write msg to log
        """
        self._logger.log(self._log_level, msg[:-1])


class MyLDAPUrl(ldap0.ldapurl.LDAPUrl):
    """
    Additional LDAP URL extension in class attributes
    """
    attr2extype = {
        'who':'bindname',
        'cred':'X-BINDPW',
        'start_tls':'startTLS',
        'trace_level':'trace',
        'pwd_filename':'X-PWDFILENAME',
        'sasl_mech':'x-saslmech',
    }


def write_ssh_file(ssh_key_path_name, new_user_ssh_keys):
    """
    write list of SSH keys into file
    """
    ssh_file = open(ssh_key_path_name, 'wb')
    ssh_file.write('\n'.join(new_user_ssh_keys))
    ssh_file.close()
    os.chmod(ssh_key_path_name, AUTHORIZED_KEY_MODE)


def parse_config_file(config_filename):
    """
    Parse sssd.conf or ldap.conf for extracting
    server URI, bind-DN and password
    """

    def split_uri_list(uri, sep):
        """
        Return list of LDAP URIs splitted from string uri
        """
        return filter(
            None,
            [
                u.strip()
                for u in uri.split(sep)
            ]
        )


    config_file = open(config_filename, 'rb')
    if config_filename.endswith('sssd.conf'):
        sep = '='
    else:
        sep = ' '
    uri_list = []
    search_base = ''
    who = None
    cred = None
    sasl_mech = None
    cacert_filename = None
    for line in config_file.readlines():
        try:
            key, value = line.strip().replace('\t', ' ').split(sep, 1)
        except (IndexError, ValueError):
            key, value = '', ''
        key = key.strip().lower()
        value = value.strip()
        if key == 'ldap_uri':
            # assume comma-separated list in sssd.conf
            uri_list = split_uri_list(value, ',')
        elif key == 'uri':
            # assume space-separated list in sssd.conf
            uri_list = split_uri_list(value, ' ')
        elif key == 'ldap_search_base' or key == 'base':
            search_base = value
        elif key == 'ldap_default_bind_dn' or key == 'binddn':
            who = value
        elif key == 'ldap_default_authtok' or key == 'bindpw':
            cred = value
        elif key == 'ldap_tls_cacert' or key == 'tls_cacertfile':
            cacert_filename = value
    return (uri_list, search_base, who, cred, sasl_mech, cacert_filename)

#-----------------------------------------------------------------------
# Main...
#-----------------------------------------------------------------------

def main():
    """
    This is the main program (you might have guessed...)
    """

    # For checking input data
    ssh_reobj = re.compile(SSH_KEY_REGEX)

    script_name = os.path.basename(sys.argv[0])


    # for writing to syslog
    from logging.handlers import SysLogHandler
    my_logger = logging.getLogger(script_name)
    my_syslog_formatter = logging.Formatter(
        fmt=script_name+' %(levelname)s %(message)s'
    )
    my_syslog_handler = logging.handlers.SysLogHandler(
        address=LOG_DEVICE,
        facility=SysLogHandler.LOG_CRON,
    )
    my_syslog_handler.setFormatter(my_syslog_formatter)

    if os.environ.get('DEBUG', 'no') == 'yes':
        my_stream_formatter = logging.Formatter(
            fmt='%(asctime)s %(levelname)s %(message)s'
        )
        my_stream_handler = logging.StreamHandler()
        my_stream_handler.setFormatter(my_stream_formatter)
        my_logger.addHandler(my_stream_handler)
        my_logger.setLevel(logging.DEBUG)
    else:
        my_logger.setLevel(logging.INFO)
    my_logger.addHandler(my_syslog_handler)

    my_logger.debug('Starting %s %s', script_name, __version__)

    # Switch off processing .ldaprc or ldap.conf
    #os.environ['LDAPNOINIT']='0'

    # Determine own system's FQDN and derive server type from that
    host_fqdn = socket.getfqdn()

    my_logger.debug('Determined server name: %s', host_fqdn)

    # Kommandozeilenargumente
    try:
        config_filename = sys.argv[1]
        path_prefix = sys.argv[2]
    except IndexError:
        my_logger.critical(
            'Abort: Incomplete command-line arguments: %s',
            ' '.join(sys.argv[1:]),
        )
        sys.exit(1)

    if not os.path.isdir(path_prefix):
        my_logger.critical(
            'Abort: %s is not a directory!',
            repr(path_prefix),
        )
        sys.exit(1)
    # Add a trailing slash if needed
    path_prefix = os.path.join(path_prefix, '')

    try:
        user_exclude_pathname = sys.argv[3]
    except IndexError:
        user_exclude_pathname = USER_EXCLUDE_FILENAME

    my_logger.debug('Reading config file: %s', repr(config_filename))
    try:
        uri_list, search_base, who, cred, sasl_mech, cacert_filename = \
            parse_config_file(config_filename)
    except CATCH_ALL_EXCEPTION, err:
        my_logger.critical(
            'Abort: Error reading config file %r: %s',
            config_filename,
            err,
        )
        sys.exit(1)
    else:
        my_logger.debug(
            (
                'parse_config_file() returned:'
                'uri_list=%r search_base=%r who=%r sasl_mech=%r cacert_filename=%r'
            ),
            uri_list,
            search_base,
            who,
            sasl_mech,
            cacert_filename,
        )
        if not uri_list:
            my_logger.critical(
                'Abort: No LDAP URIs found in config file %s',
                repr(config_filename),
            )
            sys.exit(1)
        if not search_base:
            my_logger.critical(
                'Abort: No search base found in config file %s',
                repr(config_filename),
            )
            sys.exit(1)
        my_logger.debug(
            'Found %d LDAP URIs in %s: %s',
            len(uri_list),
            repr(config_filename),
            repr(uri_list),
        )
        if sasl_mech and sasl_mech != 'EXTERNAL':
            my_logger.critical(
                'Abort: Invalid SASL mech found in configuration: %s',
                repr(sasl_mech),
            )
            sys.exit(1)
        my_logger.debug(
            'Auth info: SASL mech: %s bind-DN: %s',
            repr(sasl_mech),
            repr(who),
        )

    if os.path.islink(user_exclude_pathname):
        my_logger.critical(
            'Aborting! Link forbidden for %s',
            repr(user_exclude_pathname),
        )
        sys.exit(1)
    elif os.path.isfile(user_exclude_pathname):
        user_exclude_filenames = [user_exclude_pathname]
    elif os.path.isdir(user_exclude_pathname):
        user_exclude_filenames = glob.glob(os.path.join(user_exclude_pathname, '*'))

    my_logger.debug(
        'File(s) with excluded users: %s',
        repr(user_exclude_filenames),
    )

    excluded_users = set([])

    for fname in user_exclude_filenames:
        my_logger.debug('Reading file(s) with excluded users: %s', repr(fname))
        try:
            user_exclude_file = open(fname, 'rb')
        except Exception, err:
            my_logger.critical(
                'Aborting! Error opening %r: %s',
                fname,
                err,
            )
            sys.exit(1)
        else:
            # Read file containing user names to be ignored
            excluded_users.update([
                uid.strip()
                for uid in user_exclude_file.readlines()
                if not uid.strip().startswith('#')
            ])

    my_logger.debug(
        'Found %d excluded users in ignore file(s): %s',
        len(excluded_users),
        repr(excluded_users),
    )

    # Force server cert validation
    ldap0.set_option(ldap0.OPT_X_TLS_REQUIRE_CERT, ldap0.OPT_X_TLS_DEMAND)
    # Set path name of file containing all trusted CA certificates
    if cacert_filename:
        ldap0.set_option(ldap0.OPT_X_TLS_CACERTFILE, cacert_filename)

    pyldap_trace_level = PYLDAP_TRACELEVEL
    if pyldap_trace_level:
        pyldap_trace_file = LogWrapperFile(my_logger, logging.DEBUG)
    else:
        pyldap_trace_file = None

    ldap0.trace_level = pyldap_trace_level
    ldap0.trace_file = pyldap_trace_file


    ldapconn_retrycount = 0

    while ldapconn_retrycount < len(uri_list):

        ldap_conn_uri = uri_list[ldapconn_retrycount]
        my_logger.debug(
            'Opening LDAP connection to %s',
            repr(ldap_conn_uri),
        )

        try:
            ldapconn_retrycount += 1
            ldap_conn = ReconnectLDAPObject(
                ldap_conn_uri,
                trace_level=pyldap_trace_level,
                trace_file=pyldap_trace_file,
                retry_max=LDAP_MAXRETRYCOUNT,
                retry_delay=1.0
            )
            # Set timeout values
            ldap_conn.set_option(ldap0.OPT_NETWORK_TIMEOUT, LDAP_TIMEOUT)
            ldap_conn.set_option(ldap0.OPT_TIMEOUT, LDAP_TIMEOUT)
            # Switch of automatic referral chasing
            ldap_conn.set_option(ldap0.OPT_REFERRALS, 0)
            # Switch of automatic alias dereferencing
            ldap_conn.set_option(ldap0.OPT_DEREF, ldap0.DEREF_NEVER)
            # Use StartTLS ext.op. if necessary
            if ldap_conn_uri.lower().startswith('ldap://'):
                my_logger.debug('Send StartTLS ext.op.')
                ldap_conn.start_tls_s()
            # Now send bind request which really opens the connection
            if sasl_mech == 'EXTERNAL':
                # SASL/EXTERNAL bind to LDAP server (SSL client authc)
                my_logger.debug('SASL/EXTERNAL bind')
                ldap_conn.sasl_bind_s(None, 'EXTERNAL', '')
            else:
                # Simple bind to LDAP server
                my_logger.debug('Simple bind as %s', repr(who))
                ldap_conn.simple_bind_s(who or '', cred)
            # Try to find out the real authz-DN to deal with bind-DN rewriting
            who = ldap_conn.whoami_s()[3:]
        except ldap0.LDAPError as ldap_err:
            my_logger.debug(
                'Error opening LDAP connection (%d. LDAP URI) to %r: %s',
                ldapconn_retrycount,
                ldap_conn_uri,
                ldap_err,
            )
            if ldapconn_retrycount >= len(uri_list):
                my_logger.critical(
                    'Error opening LDAP connection to any of %r => abort',
                    uri_list,
                )
                sys.exit(1)
        except CATCH_ALL_EXCEPTION, err:
            my_logger.critical('Abort to due to unhandled exception: %s', err)
            sys.exit(1)
        else:
            my_logger.debug(
                'Successfully opened LDAP connection (%d. LDAP URI) to %r as %r',
                ldapconn_retrycount,
                ldap_conn_uri,
                ldap_conn.whoami_s(),
            )

            break

    # Assume that the server group entry is the parent entry of own server entry
    ldap_srvgrp_dn = ','.join(ldap0.dn.explode_dn(who)[1:])

    memberof_filterstr = ''
    if USE_MEMBEROF:
        try:
            # Read the server type entry
            ldap_srvgrp_result = ldap_conn.search_s(
                ldap_srvgrp_dn,
                ldap0.SCOPE_BASE,
                '(objectClass=aeSrvGroup)',
                attrlist=['cn', 'aeLoginGroups']
            )
            # Check whether exactly one LDAP search result was returned
            if len(ldap_srvgrp_result) == 1:
                _, ldap_srvgrp_entry = ldap_srvgrp_result[0]
                ssh_login_group_entries = ldap_srvgrp_entry.get('aeLoginGroups', [])
                if ssh_login_group_entries:
                    my_logger.debug(
                        'Found %d group(s) referenced (aeLoginGroups) by server group %s',
                        len(ssh_login_group_entries),
                        repr(ldap_srvgrp_dn),
                    )
                    memberof_filterstr = '(|%s)' % ''.join([
                        '(memberOf=%s)' % (group_dn)
                        for group_dn in ssh_login_group_entries
                    ])
                else:
                    my_logger.warn(
                        'No group entries found in attribute aeLoginGroups'
                        'of server group entry %s',
                        repr(ldap_srvgrp_dn),
                    )
            else:
                my_logger.warn(
                    'No search result reading server group entry %s',
                    repr(ldap_srvgrp_dn),
                )
        except Exception, err:
            my_logger.warn(
                'Unhandled exception while reading server group entry %r: %s',
                ldap_srvgrp_dn,
                err,
            )

    or_sub_filters = []
    for filter_template, pwd_max_age in USER_ENTRY_FILTERS:
        if pwd_max_age:
            pwdchangedtime_timestamp_str = time.strftime(
                '%Y%m%d%H%M%SZ',
                time.gmtime(time.time()-pwd_max_age)
            )
            pwdchangedtime_filterstr = '(pwdChangedTime>=%s)' % (
                pwdchangedtime_timestamp_str
            )
        else:
            pwdchangedtime_filterstr = ''
        or_sub_filters.append(filter_template % (
            pwdchangedtime_filterstr,
        ))
    my_logger.debug('or_sub_filters = %s', repr(or_sub_filters))

    ldap_filterstr = USER_ENTRY_BASE_FILTER_TMPL % (
        memberof_filterstr,
        ''.join(or_sub_filters),
    )

    search_start_time = time.time()
    user_attr_list = [
        'cn',
        'uid',
        'sshPublicKey'
    ]
    if RHOST_ATTR:
        user_attr_list.append(RHOST_ATTR)
    my_logger.debug(
        'Search users with filter %r, requested attributes %r',
        ldap_filterstr,
        user_attr_list,
    )
    # Grab all LDAP entries with a single synchronous search
    all_entries = ldap_conn.search_s(
        search_base,
        ldap0.SCOPE_SUBTREE,
        ldap_filterstr,
        attrlist=user_attr_list,
    )
    search_end_time = time.time()

    # Close LDAP connection
    my_logger.debug('Closing LDAP connection to %s', repr(ldap_conn_uri))
    ldap_conn.unbind_s()

    my_logger.debug(
        'Found %d LDAP entries in %0.3f s',
        len(all_entries),
        search_end_time-search_start_time
    )

    active_userid_set = set()

    for ldap_dn, ldap_entry in all_entries:

        if ldap_dn is None:
            # Silently ignore search continuations (referrals)
            break

        try:
            log_username = '%s (%s)' % (ldap_entry['cn'][0], ldap_entry['uid'][0])
        except KeyError:
            log_username = '%s' % (ldap_entry['uid'][0])

        ldap_uid = ldap_entry['uid'][0].lower()

        if ldap_uid in excluded_users:
            my_logger.debug('Ignoring user %s', repr(log_username))
            continue

        try:
            pwd.getpwnam(ldap_uid)
        except KeyError:
            my_logger.warn(
                'Username %s not found with getpwnam()',
                repr(ldap_uid)
            )
        else:
            my_logger.debug(
                'Found username %s with getpwnam()',
                repr(ldap_uid)
            )

        active_userid_set.add(ldap_uid)
        for ssh_key in ldap_entry['sshPublicKey']:
            if ssh_reobj.match(ssh_key) is None:
                my_logger.warn(
                    'Erronous SSH key in LDAP entry %s',
                    repr(ldap_dn)
                )
                continue

        if RHOST_ATTR and RHOST_ATTR in ldap_entry:
            # FIX ME! Probably we should check for correct values!
            my_logger.debug('attribute %r contains: %r', RHOST_ATTR, ldap_entry[RHOST_ATTR])
            ssh_key_prefix = 'from="%s" ' % (','.join(ldap_entry[RHOST_ATTR]))
        else:
            ssh_key_prefix = ''
        my_logger.debug('ssh_key_prefix = %r', ssh_key_prefix)

        new_user_ssh_keys = sorted([
            ''.join((ssh_key_prefix, ssh_key.strip()))
            for ssh_key in ldap_entry['sshPublicKey']
        ])

        ssh_key_path_name = os.path.join(path_prefix, ldap_uid)
        try:
            old_user_ssh_key = open(ssh_key_path_name, 'rb').read().split('\n')
        except IOError:
            my_logger.info(
                'Adding SSH key file %s for %s (mode=%04o)',
                repr(ssh_key_path_name),
                repr(log_username),
                AUTHORIZED_KEY_MODE,
            )
            write_ssh_file(ssh_key_path_name, new_user_ssh_keys)
        else:
            old_user_ssh_key.sort()
            if old_user_ssh_key != new_user_ssh_keys:
                my_logger.info(
                    'Updating SSH key file %s for %s (mode=%04o)',
                    repr(ssh_key_path_name),
                    repr(log_username),
                    AUTHORIZED_KEY_MODE,
                )
                write_ssh_file(ssh_key_path_name, new_user_ssh_keys)
            else:
                my_logger.debug(
                    'Old SSH key file unchanged %s of %s',
                    repr(ssh_key_path_name),
                    repr(log_username)
                )

    path_prefix_len = len(path_prefix)

    existing_ssh_key_files = glob.glob(os.path.join(path_prefix, '*'))
    my_logger.debug(
        '%d existing SSH key files found: %s',
        len(existing_ssh_key_files),
        repr(existing_ssh_key_files)
    )
    old_userid_set = set([
        p[path_prefix_len:]
        for p in existing_ssh_key_files
        if p[path_prefix_len:] not in excluded_users
    ])
    my_logger.debug(
        '%d existing user IDs: %s',
        len(old_userid_set),
        ', '.join(map(str, old_userid_set))
    )

    if len(active_userid_set) < EXPECTED_KEYS_MINCOUNT:
        my_logger.error(
            'Found %d instead of at least %d SSH keys => abort without deleting',
            len(active_userid_set),
            EXPECTED_KEYS_MINCOUNT,
        )
        sys.exit(2)

    to_be_removed = old_userid_set - active_userid_set

    if to_be_removed:
        my_logger.info(
            '%d existing files to be removed: %s',
            len(to_be_removed),
            ', '.join(map(str, to_be_removed))
        )
        for old_userid in to_be_removed:
            old_sshkey_filename = os.path.join(path_prefix, old_userid)
            my_logger.info('Removing SSH key file %s', repr(old_sshkey_filename))
            os.remove(old_sshkey_filename)


if __name__ == '__main__':
    main()
