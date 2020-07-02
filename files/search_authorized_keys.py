#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Export SSH keys of users from their LDAP entries into a directory
configured to hold all authorized keys (see pattern for AuthorizedKeysFile)
"""

__version__ = '0.15.0'

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
from logging.handlers import SysLogHandler

# module package ldap0
import ldap0

# module package aedir
from aedir import AEDirObject
from aedir.models import AEStatus

#-----------------------------------------------------------------------
# Configuration constants
#-----------------------------------------------------------------------

# Pathname of syslog device to be used
LOG_DEVICE = '/dev/log'

# regex pattern of acceptable SSH authorized keys
# this is handy when enforcing some rules on key comments
SSH_KEY_REGEX = '^ssh-(rsa|dss|ed25519) .+$'

# Permissions for stored authorized keys
AUTHORIZED_KEY_MODE = 0o644

# Trace level for ldap0 logging
LDAP0_TRACE_LEVEL = 0

# attribute containing valid remote host IP addresses used to generate the
# key option from="pattern-list" (set to None to disable it)
RHOST_ATTR = 'aeRemoteHost'

# Minimum number of user SSH keys expected to be found
# script exits with error code 2 and won't delete keys if less LDAP
# results than this number were received
EXPECTED_KEYS_MINCOUNT = 0

# Base filter for searching entries with attribute 'sshPublicKey'
USER_ENTRY_BASE_FILTER_TMPL = '(&(objectClass=ldapPublicKey)(sshPublicKey=*)(|{0}))'

# 1. LDAP filter part to use for searching for user entries
# 2. Time in seconds after which a password is no longer valid (password expiry)
# MUST match attribute 'pwdMaxAge' of appropriate password policy entry
# Set to None or 0 to omit pwdChangedTime filter part.
USER_ENTRY_FILTERS = (
    ('(&(objectClass=aeUser)%s)', 31536000),
    ('(objectClass=aeService)%s', None),
)

# Path name of file containing all user names to ignore
USER_EXCLUDE_FILENAME = '/etc/ssh/ignore-ssh-keyfiles'

# Timeout in seconds when connecting to local and remote LDAP servers
# used for ldap0.OPT_NETWORK_TIMEOUT and ldap0.OPT_TIMEOUT
LDAP_TIMEOUT = 5.0

# Number of times connecting to LDAP is tried
LDAP_MAXRETRYCOUNT = 4

CATCH_ALL_EXCEPTION = None
#CATCH_ALL_EXCEPTION = Exception

#-----------------------------------------------------------------------
# Classes and functions
#-----------------------------------------------------------------------


def write_ssh_file(ssh_key_path_name, new_user_ssh_keys):
    """
    write list of SSH keys into file
    """
    with open(ssh_key_path_name, 'w') as ssh_file:
        ssh_file.write('\n'.join(new_user_ssh_keys))
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


    config_file = open(config_filename, 'r+')
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
        elif key in ('ldap_search_base', 'base'):
            search_base = value
        elif key in ('ldap_default_bind_dn', 'binddn'):
            who = value
        elif key in ('ldap_default_authtok', 'bindpw'):
            cred = value
        elif key in ('ldap_tls_cacert', 'tls_cacertfile'):
            cacert_filename = value
    return (list(uri_list), search_base, who, cred, sasl_mech, cacert_filename)

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

    # Determine own system's FQDN and derive server type from that
    host_fqdn = socket.getfqdn()

    my_logger.debug('Determined server name: %s', host_fqdn)

    # Command-line arguments
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
        my_logger.critical('Abort: %r is not a directory!', path_prefix)
        sys.exit(1)
    # Add a trailing slash if needed
    path_prefix = os.path.join(path_prefix, '')

    try:
        user_exclude_pathname = sys.argv[3]
    except IndexError:
        user_exclude_pathname = USER_EXCLUDE_FILENAME

    my_logger.debug('Reading config file: %r', config_filename)
    try:
        uri_list, search_base, who, cred, sasl_mech, cacert_filename = \
            parse_config_file(config_filename)
    except CATCH_ALL_EXCEPTION as err:
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
                'Abort: No LDAP URIs found in config file %r',
                config_filename,
            )
            sys.exit(1)
        if not search_base:
            my_logger.critical(
                'Abort: No search base found in config file %r',
                config_filename,
            )
            sys.exit(1)
        my_logger.debug(
            'Found %d LDAP URIs in %r: %r',
            len(uri_list),
            config_filename,
            uri_list,
        )
        if sasl_mech and sasl_mech != 'EXTERNAL':
            my_logger.critical(
                'Abort: Invalid SASL mech found in configuration: %r',
                sasl_mech,
            )
            sys.exit(1)
        my_logger.debug(
            'Auth info: SASL mech: %r bind-DN: %r',
            sasl_mech,
            who,
        )

    if os.path.islink(user_exclude_pathname):
        my_logger.critical('Aborting! Link forbidden for %r', user_exclude_pathname)
        sys.exit(1)
    elif os.path.isfile(user_exclude_pathname):
        user_exclude_filenames = [user_exclude_pathname]
    elif os.path.isdir(user_exclude_pathname):
        user_exclude_filenames = glob.glob(os.path.join(user_exclude_pathname, '*'))
    else:
        user_exclude_filenames = []

    my_logger.debug('File(s) with excluded users: %r', user_exclude_filenames)

    excluded_users = set([])

    for fname in user_exclude_filenames:
        my_logger.debug('Reading file(s) with excluded users: %r', fname)
        try:
            user_exclude_file = open(fname, 'r+')
        except Exception as err:
            my_logger.critical('Aborting! Error opening %r: %s', fname, err)
            sys.exit(1)
        else:
            # Read file containing user names to be ignored
            excluded_users.update([
                uid.strip()
                for uid in user_exclude_file.readlines()
                if not uid.strip().startswith('#')
            ])

    my_logger.debug(
        'Found %d excluded users in ignore file(s): %r',
        len(excluded_users),
        excluded_users,
    )

    # Force server cert validation
    ldap0.set_option(ldap0.OPT_X_TLS_REQUIRE_CERT, ldap0.OPT_X_TLS_DEMAND)
    # Set path name of file containing all trusted CA certificates
    if cacert_filename:
        ldap0.set_option(ldap0.OPT_X_TLS_CACERTFILE, cacert_filename.encode('ascii'))

    ldap0._trace_level = LDAP0_TRACE_LEVEL


    ldapconn_retrycount = 0

    while ldapconn_retrycount < len(uri_list):

        ldap_conn_uri = uri_list[ldapconn_retrycount]
        my_logger.debug(
            'Opening LDAP connection to %r with simple bind as %s',
            ldap_conn_uri,
            who,
        )

        try:
            ldapconn_retrycount += 1
            ldap_conn = AEDirObject(
                ldap_conn_uri,
                trace_level=LDAP0_TRACE_LEVEL,
                retry_max=LDAP_MAXRETRYCOUNT,
                retry_delay=1.0,
                timeout=LDAP_TIMEOUT,
                who=who,
                cred=cred.encode('utf-8'),
            )
            who = ldap_conn.get_whoami_dn()
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
        except CATCH_ALL_EXCEPTION as err:
            my_logger.critical('Abort to due to unhandled exception: %s', err)
            sys.exit(1)
        else:
            my_logger.debug(
                'Successfully opened LDAP connection (%d. LDAP URI) to %r as %r',
                ldapconn_retrycount,
                ldap_conn_uri,
                ldap_conn.get_whoami_dn(),
            )

            break

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
    my_logger.debug('or_sub_filters = %r', or_sub_filters)

    ldap_filterstr = USER_ENTRY_BASE_FILTER_TMPL.format(''.join(or_sub_filters))

    search_start_time = time.time()

    user_attr_list = [
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

    ldap_results = list(ldap_conn.get_users(
        ldap_conn.get_whoami_dn(),
        ae_status=AEStatus.active,
        filterstr=ldap_filterstr,
        attrlist=user_attr_list,
        ref_attr='aeLoginGroups',
    ))

    search_end_time = time.time()

    # Close LDAP connection
    my_logger.debug('Closing LDAP connection to %s', repr(ldap_conn_uri))
    ldap_conn.unbind_s()

    my_logger.debug(
        'Found %d LDAP entries in %0.3f s',
        len(ldap_results),
        search_end_time-search_start_time
    )

    active_userid_set = set()

    for res in ldap_results:

        for user in res.rdata:

            ldap_uid = user.entry_s['uid'][0]

            if ldap_uid in excluded_users:
                my_logger.debug('Ignoring user %r', ldap_uid)
                continue

            try:
                pwd.getpwnam(ldap_uid)
            except KeyError:
                my_logger.warning('Username %r not found with getpwnam()', ldap_uid)
            else:
                my_logger.debug('Found username %s with getpwnam()', ldap_uid)

            active_userid_set.add(ldap_uid)
            for ssh_key in user.entry_s['sshPublicKey']:
                if ssh_reobj.match(ssh_key) is None:
                    my_logger.warning('Errornous SSH key in LDAP entry %s', user.dn_s)
                    continue

            if RHOST_ATTR and RHOST_ATTR in user.entry_s:
                # FIX ME! Probably we should check for correct values!
                my_logger.debug('attribute %r contains: %r', RHOST_ATTR, user.entry_s[RHOST_ATTR])
                ssh_key_prefix = 'from="%s" ' % (','.join(user.entry_s[RHOST_ATTR]))
            else:
                ssh_key_prefix = ''
            my_logger.debug('ssh_key_prefix = %r', ssh_key_prefix)

            new_user_ssh_keys = sorted([
                ''.join((ssh_key_prefix, ssh_key.strip()))
                for ssh_key in user.entry_s['sshPublicKey']
            ])

            ssh_key_path_name = os.path.join(path_prefix, ldap_uid)
            try:
                old_user_ssh_key = open(ssh_key_path_name, 'r').read().split('\n')
            except IOError:
                my_logger.info(
                    'Adding SSH key file %r for %r (mode=%04o)',
                    ssh_key_path_name,
                    ldap_uid,
                    AUTHORIZED_KEY_MODE,
                )
                write_ssh_file(ssh_key_path_name, new_user_ssh_keys)
            else:
                old_user_ssh_key.sort()
                if old_user_ssh_key != new_user_ssh_keys:
                    my_logger.info(
                        'Updating SSH key file %r for %r (mode=%04o)',
                        ssh_key_path_name,
                        ldap_uid,
                        AUTHORIZED_KEY_MODE,
                    )
                    write_ssh_file(ssh_key_path_name, new_user_ssh_keys)
                else:
                    my_logger.debug(
                        'Old SSH key file unchanged %r of %r',
                        ssh_key_path_name,
                        ldap_uid,
                    )

    path_prefix_len = len(path_prefix)

    existing_ssh_key_files = glob.glob(os.path.join(path_prefix, '*'))
    my_logger.debug(
        '%d existing SSH key files found: %r',
        len(existing_ssh_key_files),
        existing_ssh_key_files,
    )
    old_userid_set = {
        p[path_prefix_len:]
        for p in existing_ssh_key_files
        if p[path_prefix_len:] not in excluded_users
    }
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
            my_logger.info('Removing SSH key file %r', old_sshkey_filename)
            os.remove(old_sshkey_filename)


if __name__ == '__main__':
    main()
