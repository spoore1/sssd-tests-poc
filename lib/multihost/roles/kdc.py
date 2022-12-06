from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

from ..host import KDCHost
from ..ssh import SSHProcessResult
from .base import LinuxRole

if TYPE_CHECKING:
    from ..multihost import Multihost


class KDC(LinuxRole[KDCHost]):
    """
    Kerberos KDC management.
    """

    def __init__(self, mh: Multihost, role: str, host: KDCHost) -> None:
        super().__init__(mh, role, host)
        self.realm: str = host.realm

    def kadmin(self, command: str) -> SSHProcessResult:
        """
        Run kadmin command on the KDC.

        :param command: kadmin command
        :type command: str
        """
        result = self.host.ssh.exec(['kadmin.local', '-q', command])

        # Remove "Authenticating as principal root/admin@TEST with password."
        # from the output and keep only output of the command itself.
        result.stdout_lines = result.stdout_lines[1:]
        result.stdout = '\n'.join(result.stdout_lines)

        return result

    def list_principals(self) -> list[str]:
        """
        List existing Kerberos principals.

        :return: List of Kerberos principals.
        :rtype: list[str]
        """
        result = self.kadmin('listprincs')
        return result.stdout_lines

    def principal(self, name: str) -> KDCPrincipal:
        """
        Get Kerberos principal object.

        :param name: Principal name.
        :type name: str
        :return: New principal object.
        :rtype: KDCPrincipal
        """
        return KDCPrincipal(self, name)

    def config(self) -> str:
        """
        Get krb5.conf contents.

        :return: Kerberos configuration.
        :rtype: str
        """
        return textwrap.dedent(f'''
            [logging]
            default = FILE:/var/log/krb5libs.log
            kdc = FILE:/var/log/krb5kdc.log
            admin_server = FILE:/var/log/kadmind.log

            [libdefaults]
            default_realm = {self.host.realm}
            default_ccache_name = KCM:
            dns_lookup_realm = false
            dns_lookup_kdc = false
            ticket_lifetime = 24h
            renew_lifetime = 7d
            forwardable = yes

            [realms]
            {self.host.realm} = {{
              kdc = {self.host.hostname}:88
              admin_server = {self.host.hostname}:749
            }}

            [domain_realm]
            .{self.host.domain} = {self.host.realm}
            {self.host.domain} = {self.host.realm}
        ''').lstrip()


class KDCPrincipal(object):
    """
    Kerberos principals management.
    """

    def __init__(self, role: KDC, name: str) -> None:
        """
        :param role: KDC role object.
        :type role: KDC
        :param name: Principal name.
        :type name: str
        """
        self.role = role
        self.name = name

    def add(self, *, password: str = 'Secret123') -> KDCPrincipal:
        """
        Add a new Kerberos principal.

        :param password: Principal's password, defaults to 'Secret123'
        :type password: str
        :return: Self.
        :rtype: KDCPrincipal
        """
        self.role.kadmin(f'addprinc -pw "{password}" "{self.name}"')
        return self

    def get(self) -> dict[str, str]:
        """
        Retrieve principal information.

        :return: Principal information.
        :rtype: dict[str, str]
        """
        result = self.role.kadmin(f'getprinc "{self.name}"')
        out = {}
        for line in result.stdout_lines:
            (key, value) = line.split(':', maxsplit=1)
            out[key] = value.strip()

        return out

    def delete(self) -> None:
        """
        Delete existing Kerberos principal.
        """
        self.role.kadmin(f'delprinc -force "{self.name}"')

    def set_string(self, key: str, value: str) -> KDCPrincipal:
        """
        Set principal's string attribute.

        :param key: Attribute name.
        :type key: str
        :param value: Atribute value.
        :type value: str
        :return: Self.
        :rtype: KDCPrincipal
        """
        self.role.kadmin(f'setstr "{self.name}" "{key}" "{value}"')

    def get_strings(self) -> dict[str, str]:
        """
        Get all principal's string attributes.

        :return: String attributes.
        :rtype: dict[str, str]
        """
        result = self.role.kadmin(f'getstrs "{self.name}"')
        out = {}
        for line in result.stdout_lines:
            (key, value) = line.split(':', maxsplit=1)
            out[key] = value.strip()

        return out

    def get_string(self, key: str) -> str | None:
        """
        Set principal's string attribute.

        :param key: Attribute name.
        :type key: str
        :return: Attribute's value or None if not found.
        :rtype: str | None
        """
        attrs = self.get_strings()

        return attrs.get(key, None)
