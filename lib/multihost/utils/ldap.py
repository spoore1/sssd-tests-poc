from __future__ import annotations

import base64
import hashlib

import ldap
import ldap.ldapobject

from ..host import ProviderHost
from .base import MultihostUtility


class HostLDAP(MultihostUtility):
    """
    Remote host authentication.

    Provides helpers to test authentication on remote host via su, sudo and ssh.
    """

    def __init__(self, host: ProviderHost) -> None:
        """
        :param host: Remote host.
        :type host: ProviderHost
        """
        super().__init__(host)

    @property
    def conn(self) -> ldap.ldapobject.LDAPObject:
        """
        LDAP connection for direct manipulation with the directory server
        through ``python-ldap``.

        :rtype: ldap.ldapobject.LDAPObject
        """
        return self.host.conn

    @property
    def naming_context(self) -> str:
        """
        Default naming context.

        :rtype: str
        """
        return self.host.naming_context

    def hash_password(self, password: str) -> str:
        """
        Compute sha256 hash of a password that can be used as a value.

        :param password: Password to hash.
        :type password: str
        :return: Base64 of sha256 hash digest.
        :rtype: str
        """
        digest = hashlib.sha256(password.encode('utf-8')).digest()
        b64 = base64.b64encode(digest)

        return '{SHA256}' + b64.decode('utf-8')

    def dn(self, rdn: str, basedn: str | None = None) -> str:
        """
        Get distinguished name of an object.

        :param rdn: Relative DN.
        :type rdn: str
        :param basedn: Base DN, defaults to None
        :type basedn: str | None, optional
        :return: Distinguished name combined as rdn+dn+naming-context.
        :rtype: str
        """
        if not basedn:
            return f'{rdn},{self.naming_context}'

        return f'{rdn},{basedn},{self.naming_context}'

    def add(self, dn: str, attrs: dict[str, list[str]]) -> None:
        """
        Add LDAP entry.

        :param dn: Distinguished name.
        :type dn: str
        :param attrs: Attributes, key is attribute name.
        :type attrs: dict[str, list[str]]
        """
        addlist = []
        for attr, values in attrs.items():
            values = self.__values_to_bytes(values)

            # Skip if the value is None
            if values is None:
                continue

            addlist.append((attr, values))

        self.conn.add_s(dn, addlist)

    def delete(self, dn: str) -> None:
        """
        Delete LDAP entry.

        :param dn: Distinguished name.
        :type dn: str
        """
        self.conn.delete_s(dn)

    def modify(
        self,
        dn: str,
        *,
        add: dict[str, any | list[any] | None] = dict(),
        replace: dict[str, any | list[any] | None] = dict(),
        delete: dict[str, any | list[any] | None] = dict()
    ) -> None:
        """
        Modify LDAP entry.

        :param dn: Distinguished name.
        :type dn: str
        :param add: Attributes to add, defaults to dict()
        :type add: dict[str, any  |  list[any]  |  None], optional
        :param replace: Attributes to replace, defaults to dict()
        :type replace: dict[str, any  |  list[any]  |  None], optional
        :param delete: Attributes to delete, defaults to dict()
        :type delete: dict[str, any  |  list[any]  |  None], optional
        """
        modlist = []

        for attr, values in add.items():
            modlist.append((ldap.MOD_ADD, attr, self.__values_to_bytes(values)))

        for attr, values in replace.items():
            modlist.append((ldap.MOD_REPLACE, attr, self.__values_to_bytes(values)))

        for attr, values in delete.items():
            modlist.append((ldap.MOD_DELETE, attr, self.__values_to_bytes(values)))

        self.conn.modify_s(dn, modlist)

    def __values_to_bytes(self, values: any | list[any]) -> list[bytes]:
        """
        Convert values to bytes. Any value is converted to string and then
        encoded into bytes. The input can be either single value or list of
        values or None in which case None is returned.

        :param values: Values.
        :type values: any | list[any]
        :return: Values converted to bytes.
        :rtype: list[bytes]
        """
        if values is None:
            return None

        if not isinstance(values, list):
            values = [values]

        return [str(v).encode('utf-8') for v in values]
