from __future__ import annotations

import ldap
import ldap.ldapobject
import ldap.modlist

from .ssh import SSHPowerShellProcess
from .ssh import SSHProcess, SSHBashProcess, SSHClient
from typing import Type, Any,TYPE_CHECKING
from .logging import MultihostLogger

if TYPE_CHECKING:
    from .config import MultihostDomain


class MultihostHost(object):
    """
    Base multihost host class.

    .. code-block:: yaml
        :caption: Example configuration in YAML format

        - hostname: dc.ad.test
          role: ad
          username: Administrator@ad.test
          password: vagrant
          config:
            binddn: Administrator@ad.test
            bindpw: vagrant
            client:
              ad_domain: ad.test
              krb5_keytab: /enrollment/ad.keytab
              ldap_krb5_keytab: /enrollment/ad.keytab

    * Required fields: ``hostname``, ``role``, ``username``, ``password``
    * Optional fields: ``config``
    """

    def __init__(self, domain: MultihostDomain, confdict: dict[str, Any], shell: Type[SSHProcess] = SSHBashProcess):
        """
        :param domain: Multihost domain object.
        :type domain: MultihostDomain
        :param confdict: Host configuration as a dictionary.
        :type confdict: dict[str, Any]
        :param shell: Shell used in SSH connection, defaults to '/usr/bin/bash -c'.
        :type shell: str
        """
        def is_present(property: str, confdict: dict[str, Any]) -> bool:
            if '/' in property:
                (key, subpath) = property.split('/', maxsplit=1)
                if not confdict.get(key, None):
                    return False

                return is_present(subpath, confdict[key])

            return property in confdict and confdict[property]

        for required in self.required_fields:
            if not is_present(required, confdict):
                raise ValueError(f'"{required}" property is missing in host configuration')

        # Required
        self.domain: MultihostDomain = domain
        self.logger: MultihostLogger = domain.logger
        self.hostname: str = confdict['hostname']
        self.role: str = confdict['role']
        self.username: str = confdict['username']
        self.password: str = confdict['password']

        # Optional
        self.config = confdict.get('config', {})

        # SSH connection
        self.ssh: SSHClient = SSHClient(
            host=self.hostname,
            user=self.username,
            password=self.password,
            logger=self.logger,
            shell=shell,
        )

        self.ssh.connect()

    @property
    def required_fields(self) -> list[str]:
        return ['hostname', 'role', 'username', 'password']

    def backup(self) -> None:
        """
        Backup host.
        """
        pass

    def restore(self) -> None:
        """
        Restore host to its original state.
        """
        pass


class ProviderHost(MultihostHost):
    """
    Generic provider host.

    Provides access to LDAP connection for direct manipulation with remote
    directory server.
    """

    def __init__(self, *args, tls: bool = True, **kwargs):
        """
        :param \\*args: MultihostHost arguments.
        :type \\*args: Any
        :param \\*kwargs: MultihostHost keyword arguments.
        :type \\*kwargs: Any
        :param tls: Require TLS connection, defaults to True
        :type tls: bool, optional
        """
        super().__init__(*args, **kwargs)
        self.client: dict[str, any] = self.config.get('client', {})

        self.tls = tls
        self.uri = f'ldap://{self.hostname}'
        self.binddn = self.config.get('binddn', 'cn=Directory Manager')
        self.bindpw = self.config.get('bindpw', 'Secret123')

        # Lazy properties.
        self.__conn = None
        self.__naming_context = None

    @property
    def conn(self) -> ldap.ldapobject.LDAPObject:
        """
        LDAP connection (``python-ldap`` library).

        :rtype: ldap.ldapobject.LDAPObject
        """
        if not self.__conn:
            newconn = ldap.initialize(self.uri)
            newconn.protocol_version = ldap.VERSION3
            newconn.set_option(ldap.OPT_REFERRALS, 0)

            if self.tls:
                newconn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
                newconn.start_tls_s()

            newconn.simple_bind_s(self.binddn, self.bindpw)
            self.__conn = newconn

        return self.__conn

    def disconnect(self) -> None:
        """
        Disconnect LDAP connection.
        """
        if self.__conn is not None:
            self.__conn.unbind()
            self.__conn = None

    @property
    def naming_context(self) -> str:
        """
        Default naming context.

        :raises ValueError: If default naming context can not be obtained.
        :rtype: str
        """
        if not self.__naming_context:
            attr = 'defaultNamingContext'
            result = self.conn.search_s('', ldap.SCOPE_BASE, attrlist=[attr])
            if len(result) != 1:
                raise ValueError(f'Unexpected number of results for rootDSE query: {len(result)}')

            (_, values) = result[0]
            if attr not in values:
                raise ValueError(f'Unable to find {attr}')

            self.__naming_context = str(values[attr][0].decode('utf-8'))

        return self.__naming_context

    def ldap_result_to_dict(self, result: tuple[str, dict[str, list[bytes]]]) -> dict[str, dict[str, list[bytes]]]:
        """
        Convert result from python-ldap library from tuple into a dictionary
        to simplify lookup by distinguished name.

        :param result: Search result from python-ldap.
        :type result: tuple[str, dict[str, list[bytes]]]
        :return: Dictionary with distinguished name as key and attributes as value.
        :rtype: dict[str, dict[str, list[bytes]]]
        """
        return dict((dn, attrs) for dn, attrs in result if dn is not None)


class LDAPHost(ProviderHost):
    """
    LDAP host object.

    Provides features specific for native directory server like 389ds.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # Additional client configuration
        self.client.setdefault('id_provider', 'ldap')
        self.client.setdefault('ldap_uri', self.uri)

        # Backup of original data
        self.__backup: dict[str, dict[str, list[bytes]]] = None

    def backup(self) -> None:
        """
        Backup all directory server data.

        Full backup of ``cn=config`` and default naming context is performed.
        This is done by simple LDAP search on given base dn and remembering the
        contents. The operation is usually very fast.
        """
        if self.__backup is not None:
            return

        data = self.conn.search_s(self.naming_context, ldap.SCOPE_SUBTREE)
        config = self.conn.search_s('cn=config', ldap.SCOPE_BASE)

        dct = self.ldap_result_to_dict(data)
        dct.update(self.ldap_result_to_dict(config))
        self.__backup = dct

    def restore(self) -> None:
        """
        Restore directory server data.

        Current directory server content in ``cn=config`` and default naming
        context is modified to its original data. This is done by computing a
        difference between original data obtained by :func:`backup` and then
        calling add, delete and modify operations to convert current state to
        the original state. This operation is usually very fast.
        """
        data = self.conn.search_s(self.naming_context, ldap.SCOPE_SUBTREE)
        config = self.conn.search_s('cn=config', ldap.SCOPE_BASE)

        # Convert list of tuples to dictionary for better lookup
        data = self.ldap_result_to_dict(data)
        data.update(self.ldap_result_to_dict(config))

        for dn, attrs in reversed(data.items()):
            # Restore records that were modified
            if dn in self.__backup:
                original_attrs = self.__backup[dn]
                modlist = ldap.modlist.modifyModlist(attrs, original_attrs)
                modlist = self.__filter_modlist(dn, modlist)
                if modlist:
                    self.conn.modify_s(dn, modlist)

        for dn, attrs in reversed(data.items()):
            # Delete records that were added
            if dn not in self.__backup:
                self.conn.delete_s(dn)
                continue

        for dn, attrs in self.__backup.items():
            # Add back records that were deleted
            if dn not in data:
                self.conn.add_s(dn, list(attrs.items()))

    def __filter_modlist(self, dn, modlist: list) -> list:
        if dn != 'cn=config':
            return modlist

        result = []
        for (op, attr, value) in modlist:
            # We are not allowed to touch these
            if attr.startswith('nsslapd'):
                continue

            result.append((op, attr, value))

        return result


class IPAHost(ProviderHost):
    """
    IPA host object.

    Provides features specific for IPA server.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.adminpw = self.config.get('adminpw', 'Secret123')

        # Additional client configuration
        self.client.setdefault('id_provider', 'ipa')
        self.client.setdefault('access_provider', 'ipa')
        self.client.setdefault('ipa_server', self.hostname)
        self.client.setdefault('dyndns_update', False)

        # Backup of original data
        self.__backup: str = None

    def kinit(self) -> None:
        """
        Obtain ``admin`` user Kerberos TGT.
        """
        self.ssh.exec(['kinit', 'admin'], input=self.adminpw)

    def backup(self) -> None:
        """
        Backup all IPA server data.

        This is done by calling ``ipa-backup --data --online`` on the server
        and can take several seconds to finish.
        """
        if self.__backup is not None:
            return

        self.ssh.run('ipa-backup --data --online')
        cmd = self.ssh.run('ls /var/lib/ipa/backup | tail -n 1')
        self.__backup = cmd.stdout.strip()

    def restore(self) -> None:
        """
        Restore all IPA server data to its original state.

        This is done by calling ``ipa-restore --data --online`` on the server
        and can take several seconds to finish.
        """
        if self.__backup is None:
            return

        self.ssh.exec(['ipa-restore', '--unattended', '--password', self.bindpw, '--data', '--online', self.__backup])


class SambaHost(ProviderHost):
    """
    Samba host object.

    Provides features specific for Samba server.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # Additional client configuration
        self.client.setdefault('id_provider', 'ad')
        self.client.setdefault('access_provider', 'ad')
        self.client.setdefault('ad_server', self.hostname)
        self.client.setdefault('dyndns_update', False)

        # Backup of original data
        self.__backup: bool = None

    def backup(self) -> None:
        """
        Backup all Samba server data.

        This is done by creating a backup of Samba database. This operation
        is usually very fast.
        """
        if self.__backup is not None:
            return

        self.ssh.run('''
            set -e
            systemctl stop samba
            rm -fr /var/lib/samba.bak
            cp -r /var/lib/samba /var/lib/samba.bak
            systemctl start samba

            # systemctl finishes before samba is fully started, wait for it to start listening on ldap port
            timeout 5s bash -c 'until netstat -ltp 2> /dev/null | grep :ldap &> /dev/null; do :; done'
        ''')
        self.__backup = True

    def restore(self) -> None:
        """
        Restore all Samba server data to its original value.

        This is done by overriding current database with the backup created
        by :func:`backup`. This operation is usually very fast.
        """
        if self.__backup is None:
            return

        self.disconnect()

        self.ssh.run('''
            set -e
            systemctl stop samba
            rm -fr /var/lib/samba
            cp -r /var/lib/samba.bak /var/lib/samba
            systemctl start samba
            samba-tool ntacl sysvolreset

            # systemctl finishes before samba is fully started, wait for it to start listening on ldap port
            timeout 5s bash -c 'until netstat -ltp 2> /dev/null | grep :ldap &> /dev/null; do :; done'
        ''')

        self.disconnect()


class ADHost(ProviderHost):
    """
    Active Directory host object.

    Provides features specific for Active Directory domain controller.

    .. warning::

        Backup and restore functionality of a domain controller is quite limited
        when compared to other services. Unfortunately, a full backup and
        restore of a domain controller is not possible without a complete system
        backup and reboot which takes too long time and is not suitable for
        setting an exact state for each test. Therefore a limited backup and
        restore is provided which only deletes all added objects. It works well
        if a test does not modify any existing data but only uses new
        objects like newly added users and groups.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, shell=SSHPowerShellProcess)

        # Additional client configuration
        self.client.setdefault('id_provider', 'ad')
        self.client.setdefault('access_provider', 'ad')
        self.client.setdefault('ad_server', self.hostname)
        self.client.setdefault('dyndns_update', False)

        # Backup of original data
        self.__backup: bool = False

        # Lazy properties
        self.__naming_context = None

    @property
    def conn(self) -> ldap.ldapobject.LDAPObject:
        """
        It is recommended to use Powershell to manage Active Directory instead direct LDAP access due to issues with
        TLS/SSL connections on Windows 2012 server. Trying to use this property will raise an Exception.
        """
        raise Exception('You should not talk with Active Directory through LDAP. Use Powershell instead.')

    @property
    def naming_context(self) -> str:
        """
        Default naming context.

        :raises ValueError: If default naming context can not be obtained.
        :rtype: str
        """
        if not self.__naming_context:
            result = self.ssh.run('Write-Host (Get-ADRootDSE).rootDomainNamingContext')
            nc = result.stdout.strip()
            if not nc:
                raise ValueError('Unable to find default naming context')

            self.__naming_context = nc

        return self.__naming_context

    def disconnect(self) -> None:
        return

    def backup(self) -> None:
        """
        Perform limited backup of the domain controller data. Currently only
        content under ``$default_naming_context`` is backed up.

        This is done by performing simple LDAP search on the base dn. This
        operation is usually very fast.
        """
        if self.__backup:
            return

        self.ssh.run(fr'''
        Remove-Item C:\multihost_backup.txt
        $result = Get-ADObject -SearchBase '{self.naming_context}' -Filter "*"
        foreach ($r in $result) {{
            $r.DistinguishedName | Add-Content -Path C:\multihost_backup.txt
        }}
        ''')

        self.__backup = True

    def restore(self) -> None:
        """
        Perform limited restoration of the domain controller state.

        This is done by removing all records under ``$default_naming_context``
        that are not present in the original state.
        """

        self.ssh.run(fr'''
        $backup = Get-Content C:\multihost_backup.txt
        $result = Get-ADObject -SearchBase '{self.naming_context}' -Filter "*"
        foreach ($r in $result) {{
            if (!$backup.contains($r.DistinguishedName)) {{
                Write-Host "Removing: $r"
                Try {{
                   Remove-ADObject -Identity $r.DistinguishedName -Recursive -Confirm:$False
                }} Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {{
                    # Ignore not found error as the object may have been deleted by recursion
                }}
            }}
        }}

        # If we got here, make sure we exit with 0
        Exit 0
        ''')


class NFSHost(MultihostHost):
    """
    NFS server host object.

    Provides NFS service management.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.exports_dir = self.config.get('exports_dir', '/exports').rstrip('/')

        # Backup of original data
        self.__backup: bool = False

    def backup(self) -> None:
        """
        Backup NFS server.
        """
        if self.__backup:
            return

        self.ssh.run(fr'''
        tar --ignore-failed-read -czvf /tmp/mh.nfs.backup.tgz "{self.exports_dir}" /etc/exports /etc/exports.d
        ''')

        self.__backup = True

    def restore(self) -> None:
        """
        Restore NFS server to its initial contents.
        """

        self.ssh.run(fr'''
        rm -fr "{self.exports_dir}/*"
        rm -fr /etc/exports.d/*
        tar -xf /tmp/mh.nfs.backup.tgz -C /
        exportfs -r
        ''')
