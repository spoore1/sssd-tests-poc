from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

import ldap
import ldap.ldapobject

from ..host import LDAPHost
from ..utils.ldap import HostLDAP
from .base import BaseObject, LinuxRole
from .nfs import NFSExport

if TYPE_CHECKING:
    from ..multihost import Multihost


class LDAP(LinuxRole):
    """
    LDAP service management.
    """

    def __init__(self, mh: Multihost, role: str, host: LDAPHost) -> None:
        super().__init__(mh, role, host, user_cls=LDAPUser, group_cls=LDAPGroup)

        self.ldap: HostLDAP = HostLDAP(host)
        self.auto_uid: int = 23000
        self.auto_gid: int = 33000
        self.auto_ou: dict[str, bool] = {}

        self.automount: LDAPAutomount = LDAPAutomount(self)
        """
        Provides API to manipulate automount objects.
        """

    def setup(self) -> None:
        """
        Setup LDAP role.

        #. backup LDAP data
        """
        super().setup()
        self.host.backup()

    def teardown(self) -> None:
        """
        Teardown LDAP role.

        #. restore original LDAP data
        """
        self.host.restore()
        super().teardown()

    def _generate_uid(self) -> int:
        """
        Generate next user id value.

        :return: User id.
        :rtype: int
        """
        self.auto_uid += 1
        return self.auto_uid

    def _generate_gid(self) -> int:
        """
        Generate next group id value.

        :return: Group id.
        :rtype: int
        """
        self.auto_gid += 1
        return self.auto_gid

    def ou(self, name: str, basedn: LDAPObject | str | None = None) -> LDAPOrganizationalUnit:
        """
        Get organizational unit object.

        :param name: Unit name.
        :type name: str
        :param basedn: Base dn, defaults to None
        :type basedn: LDAPObject | str | None, optional
        :return: New organizational unit object.
        :rtype: LDAPOrganizationalUnit
        """
        return LDAPOrganizationalUnit(self, name, basedn)

    def user(self, name: str, basedn: LDAPObject | str | None = 'ou=users') -> LDAPUser:
        """
        Get user object.

        :param name: User name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=users``
        :type basedn: LDAPObject | str | None, optional
        :return: New user object.
        :rtype: LDAPUser
        """
        return LDAPUser(self, name, basedn)

    def group(self, name: str, basedn: LDAPObject | str | None = 'ou=groups', *, rfc2307bis: bool = False) -> LDAPGroup:
        """
        Get user object.

        :param name: Group name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=groups``
        :type basedn: LDAPObject | str | None, optional
        :param rfc2307bis: If True, rfc2307bis schema is used, defaults to False
        :type rfc2307bis: bool, optional
        :return: New group object.
        :rtype: LDAPGroup
        """

        return LDAPGroup(self, name, basedn, rfc2307bis=rfc2307bis)

    def sudorule(self, name: str, basedn: LDAPObject | str | None = 'ou=sudoers') -> LDAPSudoRule:
        """
        Get sudo rule object.

        :param name: Rule name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=sudoers``
        :type basedn: LDAPObject | str | None, optional
        :return: New sudo rule object.
        :rtype: LDAPSudoRule
        """

        return LDAPSudoRule(self, name, basedn)


class LDAPObject(BaseObject):
    def __init__(
        self,
        role: LDAP,
        rdn: str,
        basedn: LDAPObject | str | None = None,
        default_ou: str | None = None
    ) -> None:
        """
        :param role: LDAP role object.
        :type role: LDAP
        :param rdn: Relative distinguished name.
        :type rdn: str
        :param basedn: Base dn, defaults to None
        :type basedn: LDAPObject | str | None, optional
        :param default_ou: Name of default organizational unit that is automatically
                           created if basedn is set to ou=$default_ou, defaults to None.
        :type default_ou: str | None, optional
        """
        super().__init__()
        self.role = role
        self.rdn = rdn
        self.basedn = basedn
        self.dn = self._dn(rdn, basedn)
        self.default_ou = default_ou

        self.__create_default_ou(basedn, self.default_ou)

    def __create_default_ou(self, basedn: LDAPObject | str | None, default_ou: str | None) -> None:
        if basedn is None or not isinstance(basedn, str):
            return

        if basedn.lower() != f'ou={default_ou}' or default_ou in self.role.auto_ou:
            return

        self.role.ou(default_ou).add()
        self.role.auto_ou[default_ou] = True

    def _dn(self, rdn: str, basedn: LDAPObject | str | None = None) -> str:
        """
        Get distinguished name of an object.

        :param rdn: Relative DN.
        :type rdn: str
        :param basedn: Base DN, defaults to None
        :type basedn: LDAPObject | str | None, optional
        :return: Distinguished name combined from rdn+dn+naming-context.
        :rtype: str
        """
        if isinstance(basedn, LDAPObject):
            return f'{rdn},{basedn.dn}'

        return self.role.ldap.dn(rdn, basedn)

    def _default(self, value: any, default: any) -> any:
        """
        :return: Value if not None, default value otherwise.
        :rtype: any
        """
        if value is None:
            return default

        return value

    def _hash_password(self, password: str | None | LDAP.Flags) -> str | None | LDAP.Flags:
        """
        Compute sha256 hash of a password that can be used as a value.

        Return original value If password is none or LDAP.Flags member.

        :param password: Password to hash.
        :type password: str
        :return: Base64 of sha256 hash digest.
        :rtype: str
        """
        if password is None or isinstance(password, LDAP.Flags):
            # Return unchanged value to simplify attribute modification
            return password

        return self.role.ldap.hash_password(password)

    def _add(self, attrs: dict[str, list[str]]) -> None:
        self.role.ldap.add(self.dn, attrs)

    def _modify(
        self,
        *,
        add: dict[str, any | list[any] | None] = dict(),
        replace: dict[str, any | list[any] | None] = dict(),
        delete: dict[str, any | list[any] | None] = dict()
    ) -> None:
        self.role.ldap.modify(self.dn, add=add, replace=replace, delete=delete)

    def _set(self, attrs: dict[str, any]) -> None:
        replace = {}
        delete = {}
        for attr, value in attrs.items():
            if value is None:
                continue

            if value == LDAP.Flags.DELETE:
                delete[attr] = None
                continue

            replace[attr] = value

        self.role.ldap.modify(self.dn, replace=replace, delete=delete)

    def delete(self) -> None:
        """
        Delete object from LDAP.
        """
        self.role.ldap.delete(self.dn)

    def get(self, attrs: list[str] | None = None, opattrs: bool = False) -> dict[str, list[str]]:
        """
        Get LDAP object attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :param opattrs: If True, operational attributes are returned as well, defaults to False
        :type opattrs: bool, optional
        :raises ValueError: If multiple objects with the same dn exists.
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        attrs = ['*'] if attrs is None else attrs
        if opattrs:
            attrs.append('+')

        result = self.role.ldap.conn.search_s(self.dn, ldap.SCOPE_BASE, attrlist=attrs)
        if not result:
            return None

        if len(result) != 1:
            raise ValueError(f'Multiple objects returned on base search for {self.dn}')

        (_, attrs) = result[0]

        return {k: [i.decode('utf-8') for i in v] for k, v in attrs.items()}


class LDAPOrganizationalUnit(LDAPObject):
    """
    LDAP organizational unit management.
    """

    def __init__(self, role: LDAP, name: str, basedn: LDAPObject | str | None = None) -> None:
        """
        :param role: LDAP role object.
        :type role: LDAP
        :param name: Unit name.
        :type name: str
        :param basedn: Base dn, defaults to None
        :type basedn: LDAPObject | str | None, optional
        """
        super().__init__(role, f'ou={name}', basedn)
        self.name = name

    def add(self) -> LDAPOrganizationalUnit:
        """
        Create new LDAP organizational unit.

        :return: Self.
        :rtype: LDAPOrganizationalUnit
        """
        attrs = {
            'objectClass': 'organizationalUnit',
            'ou': self.name
        }

        self._add(attrs)
        return self


class LDAPUser(LDAPObject):
    """
    LDAP user management.
    """

    def __init__(self, role: LDAP, name: str, basedn: LDAPObject | str | None = 'ou=users') -> None:
        """
        :param role: LDAP role object.
        :type role: LDAP
        :param name: User name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=users``
        :type basedn: LDAPObject | str | None, optional
        """
        super().__init__(role, f'cn={name}', basedn, default_ou='users')
        self.name = name

    def add(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str | None = 'Secret123',
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
        shadowMin: int | None = None,
        shadowMax: int | None = None,
        shadowWarning: int | None = None,
        shadowLastChange: int | None = None
    ) -> LDAPUser:
        """
        Create new LDAP user.

        User and group id is assigned automatically if they are not set. Other
        parameters that are not set are ignored.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param password: Password, defaults to 'Secret123'
        :type password: str, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :param shadowMin: shadowmin LDAP attribute, defaults to None
        :type shadowMin: int | None, optional
        :param shadowMax: shadowmax LDAP attribute, defaults to None
        :type shadowMax: int | None, optional
        :param shadowWarning: shadowwarning LDAP attribute, defaults to None
        :type shadowWarning: int | None, optional
        :param shadowLastChange: shadowlastchage LDAP attribute, defaults to None
        :type shadowLastChange: int | None, optional
        :return: Self.
        :rtype: LDAPUser
        """
        # Assign uid and gid automatically if not present to have the same
        # interface as other services.
        if uid is None:
            uid = self.role._generate_uid()

        if gid is None:
            gid = uid

        attrs = {
            'objectClass': ['posixAccount'],
            'cn': self.name,
            'uid': self.name,
            'uidNumber': uid,
            'gidNumber': gid,
            'homeDirectory': self._default(home, f'/home/{self.name}'),
            'userPassword': self._hash_password(password),
            'gecos': gecos,
            'loginShell': shell,
            'shadowMin': shadowMin,
            'shadowMax': shadowMax,
            'shadowWarning': shadowWarning,
            'shadowLastChange': shadowLastChange,
        }

        if self._remove_none_from_list([shadowMin, shadowMax, shadowWarning, shadowLastChange]):
            attrs['objectClass'].append("shadowAccount")

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        uid: int | LDAP.Flags | None = None,
        gid: int | LDAP.Flags | None = None,
        password: str | LDAP.Flags | None = None,
        home: str | LDAP.Flags | None = None,
        gecos: str | LDAP.Flags | None = None,
        shell: str | LDAP.Flags | None = None,
        shadowMin: int | LDAP.Flags | None = None,
        shadowMax: int | LDAP.Flags | None = None,
        shadowWarning: int | LDAP.Flags | None = None,
        shadowLastChange: int | LDAP.Flags | None = None,
    ) -> LDAPUser:
        """
        Modify existing LDAP user.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to ``LDAP.Flags.DELETE``.

        :param uid: User id, defaults to None
        :type uid: int | LDAP.Flags | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | LDAP.Flags | None, optional
        :param home: Home directory, defaults to None
        :type home: str | LDAP.Flags | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | LDAP.Flags | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | LDAP.Flags | None, optional
        :param shadowMin: shadowmin LDAP attribute, defaults to None
        :type shadowMin: int | LDAP.Flags | None, optional
        :param shadowMax: shadowmax LDAP attribute, defaults to None
        :type shadowMax: int | LDAP.Flags | None, optional
        :param shadowWarning: shadowwarning LDAP attribute, defaults to None
        :type shadowWarning: int | LDAP.Flags | None, optional
        :param shadowLastChange: shadowlastchage LDAP attribute, defaults to None
        :type shadowLastChange: int | LDAP.Flags | None, optional
        :return: Self.
        :rtype: LDAPUser
        """
        attrs = {
            'uidNumber': uid,
            'gidNumber': gid,
            'homeDirectory': home,
            'userPassword': self._hash_password(password),
            'gecos': gecos,
            'loginShell': shell,
            'shadowMin': shadowMin,
            'shadowMax': shadowMax,
            'shadowWarning': shadowWarning,
            'shadowLastChange': shadowLastChange,
        }

        self._set(attrs)
        return self


class LDAPGroup(LDAPObject):
    """
    LDAP group management.
    """

    def __init__(
        self,
        role: LDAP,
        name: str,
        basedn: LDAPObject | str | None = 'ou=groups',
        *,
        rfc2307bis: bool = False
    ) -> None:
        """
        :param role: LDAP role object.
        :type role: LDAP
        :param name: Group name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=groups``
        :type basedn: LDAPObject | str | None, optional
        :param rfc2307bis: If True, rfc2307bis schema is used, defaults to False
        :type rfc2307bis: bool, optional
        """
        super().__init__(role, f'cn={name}', basedn, default_ou='groups')
        self.name = name
        self.rfc2307bis = rfc2307bis

        if not self.rfc2307bis:
            self.object_class = ['posixGroup']
            self.member_attr = 'memberUid'
        else:
            self.object_class = ['posixGroup', 'groupOfNames']
            self.member_attr = 'member'

    def __members(self, values: list[LDAPUser | LDAPGroup | str]) -> list[str] | None:
        if values is None:
            return None

        if self.rfc2307bis:
            return [x.dn if isinstance(x, LDAPObject) else self._dn(x) for x in values]

        return [x.name if isinstance(x, LDAPObject) else x for x in values]

    def add(
        self,
        *,
        gid: int | None = None,
        members: list[LDAPUser | LDAPGroup | str] | None = None,
        password: str | None = None,
        description: str | None = None,
    ) -> LDAPGroup:
        """
        Create new LDAP group.

        Group id is assigned automatically if it is not set. Other parameters
        that are not set are ignored.

        :param gid: _description_, defaults to None
        :type gid: int | None, optional
        :param members: List of group members, defaults to None
        :type members: list[LDAPUser  |  LDAPGroup  |  str] | None, optional
        :param password: Group password, defaults to None
        :type password: str | None, optional
        :param description: Description, defaults to None
        :type description: str | None, optional
        :return: Self.
        :rtype: LDAPGroup
        """
        # Assign gid automatically if not present to have the same
        # interface as other services.
        if gid is None:
            gid = self.role._generate_gid()

        attrs = {
            'objectClass': self.object_class,
            'cn': self.name,
            'gidNumber': gid,
            'userPassword': self._hash_password(password),
            'description': description,
            self.member_attr: self.__members(members),
        }

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        gid: int | LDAP.Flags | None = None,
        members: list[LDAPUser | LDAPGroup | str] | LDAP.Flags | None = None,
        password: str | LDAP.Flags | None = None,
        description: str | LDAP.Flags | None = None,
    ) -> LDAPGroup:
        """
        Modify existing LDAP group.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to ``LDAP.Flags.DELETE``.

        :param gid: Group id, defaults to None
        :type gid: int | LDAP.Flags | None, optional
        :param members: List of group members, defaults to None
        :type members: list[LDAPUser  |  LDAPGroup  |  str] | LDAP.Flags | None, optional
        :param password: Group password, defaults to None
        :type password: str | LDAP.Flags | None, optional
        :param description: Description, defaults to None
        :type description: str | LDAP.Flags | None, optional
        :return: Self.
        :rtype: LDAPGroup
        """
        attrs = {
            'gidNumber': gid,
            'userPassword': self._hash_password(password),
            'description': description,
            self.member_attr: self.__members(members),
        }

        self._set(attrs)
        return self

    def add_member(self, member: LDAPUser | LDAPGroup | str) -> LDAPGroup:
        """
        Add group member.

        :param member: User or group (on rfc2307bis schema) to add as a member.
        :type member: LDAPUser | LDAPGroup | str
        :return: Self.
        :rtype: LDAPGroup
        """
        return self.add_members([member])

    def add_members(self, members: list[LDAPUser | LDAPGroup | str]) -> LDAPGroup:
        """
        Add multiple group members.

        :param members: Users or groups (on rfc2307bis schema) to add as members.
        :type members: list[LDAPUser | LDAPGroup | str]
        :return: Self.
        :rtype: LDAPGroup
        """
        self._modify(add={self.member_attr: self.__members(members)})
        return self

    def remove_member(self, member: LDAPUser | LDAPGroup | str) -> LDAPGroup:
        """
        Remove group member.

        :param member: User or group (on rfc2307bis schema) to add as a member.
        :type member: LDAPUser | LDAPGroup | str
        :return: Self.
        :rtype: LDAPGroup
        """
        return self.remove_members([member])

    def remove_members(self, members: list[LDAPUser | LDAPGroup | str]) -> LDAPGroup:
        """
        Remove multiple group members.

        :param members: Users or groups (on rfc2307bis schema) to add as members.
        :type members: list[LDAPUser | LDAPGroup | str]
        :return: Self.
        :rtype: LDAPGroup
        """
        self._modify(delete={self.member_attr: self.__members(members)})
        return self


class LDAPSudoRule(LDAPObject):
    """
    LDAP sudo rule management.
    """

    def __init__(
        self,
        role: LDAP,
        name: str,
        basedn: LDAPObject | str | None = 'ou=sudoers',
    ) -> None:
        """
        :param role: LDAP role object.
        :type role: LDAP
        :param name: Sudo rule name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=sudoers``
        :type basedn: LDAPObject | str | None, optional
        """
        super().__init__(role, f'cn={name}', basedn, default_ou='sudoers')
        self.name = name

    def add(
        self,
        *,
        user: int | str | LDAPUser | LDAPGroup | list[int | str | LDAPUser | LDAPGroup] | None = None,
        host: str | list[str] | None = None,
        command: str | list[str] | None = None,
        option: str | list[str] | None = None,
        runasuser: int | str | LDAPUser | LDAPGroup | list[int | str | LDAPUser | LDAPGroup] | None = None,
        runasgroup: int | str | LDAPGroup | list[int | str | LDAPGroup] | None = None,
        notbefore: str | list[str] | None = None,
        notafter: str | list[str] | None = None,
        order: int | list[int] | None = None,
        nopasswd: bool | None = None
    ) -> LDAPSudoRule:
        """
        Create new sudo rule.

        :param user: sudoUser attribute, defaults to None
        :type user: int | str | LDAPUser | LDAPGroup | list[int | str | LDAPUser | LDAPGroup], optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str], optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str], optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None
        :type runasuser: int | str | LDAPUser | LDAPGroup | list[int | str | LDAPUser | LDAPGroup] | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: int | str | LDAPGroup | list[int | str | LDAPGroup] | None, optional
        :param notbefore: sudoNotBefore attribute, defaults to None
        :type notbefore: str | list[str] | None, optional
        :param notafter: sudoNotAfter attribute, defaults to None
        :type notafter: str | list[str] | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | list[int] | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: Self.
        :rtype: LDAPSudoRule
        """
        attrs = {
            'objectClass': 'sudoRole',
            'cn': self.name,
            'sudoUser': self.__sudo_user(user),
            'sudoHost': host,
            'sudoCommand': command,
            'sudoOption': option,
            'sudoRunAsUser': self.__sudo_user(runasuser),
            'sudoRunAsGroup': self.__sudo_group(runasgroup),
            'sudoNotBefore': notbefore,
            'sudoNotAfter': notafter,
            'sudoOrder': order,
        }

        if nopasswd is True:
            attrs['sudoOption'] = self._include_attr_value(attrs['sudoOption'], '!authenticate')
        elif nopasswd is False:
            attrs['sudoOption'] = self._include_attr_value(attrs['sudoOption'], 'authenticate')

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        user: int | str | LDAPUser | LDAPGroup | list[int | str | LDAPUser | LDAPGroup] | LDAP.Flags | None = None,
        host: str | list[str] | LDAP.Flags | None = None,
        command: str | list[str] | LDAP.Flags | None = None,
        option: str | list[str] | LDAP.Flags | None = None,
        runasuser: int | str | LDAPUser | LDAPGroup | list[int | str | LDAPUser | LDAPGroup] | LDAP.Flags | None = None,
        runasgroup: int | str | LDAPGroup | list[int | str | LDAPGroup] | LDAP.Flags | None = None,
        notbefore: str | list[str] | LDAP.Flags | None = None,
        notafter: str | list[str] | LDAP.Flags | None = None,
        order: int | list[int] | LDAP.Flags | None = None,
        nopasswd: bool | None = None
    ) -> LDAPSudoRule:
        """
        Modify existing sudo rule.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to ``LDAP.Flags.DELETE``.

        :param user: sudoUser attribute, defaults to None
        :type user: int | str | LDAPUser | LDAPGroup | list[int | str | LDAPUser | LDAPGroup]
          | LDAP.Flags | None, optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str] | LDAP.Flags | None, optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str] | LDAP.Flags | None, optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | LDAP.Flags | None, optional
        :param runasuser: sudoRunAsUsere attribute, defaults to None
        :type runasuser: int | str | LDAPUser | LDAPGroup | list[int | str | LDAPUser | LDAPGroup]
          | LDAP.Flags | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: int | str | LDAPGroup | list[int | str | LDAPGroup] | LDAP.Flags | None, optional
        :param notbefore: sudoNotBefore attribute, defaults to None
        :type notbefore: str | list[str] | LDAP.Flags | None, optional
        :param notafter: sudoNotAfter attribute, defaults to None
        :type notafter: str | list[str] | LDAP.Flags | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | list[int] | LDAP.Flags | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: Self.
        :rtype: LDAPSudoRule
        """
        attrs = {
            'objectClass': 'sudoRole',
            'cn': self.name,
            'sudoUser': self.__sudo_user(user),
            'sudoHost': host,
            'sudoCommand': command,
            'sudoOption': option,
            'sudoRunAsUser': self.__sudo_user(runasuser),
            'sudoRunAsGroup': self.__sudo_group(runasgroup),
            'sudoNotBefore': notbefore,
            'sudoNotAfter': notafter,
            'sudoOrder': order,
        }

        if nopasswd is True:
            attrs['sudoOption'] = self._include_attr_value(attrs['sudoOption'], '!authenticate')
        elif nopasswd is False:
            attrs['sudoOption'] = self._include_attr_value(attrs['sudoOption'], 'authenticate')

        self._set(attrs)
        return self

    def __sudo_user(
        self,
        sudo_user: None | LDAP.Flags | str | LDAPUser | LDAPGroup | list[str | LDAPUser | LDAPGroup]
    ) -> list[str]:
        def _get_value(value: str | LDAPUser | LDAPGroup):
            if isinstance(value, self.role._user_cls):
                return value.name

            if isinstance(value, self.role._group_cls):
                return '%' + value.name

            if isinstance(value, str):
                return value

            if isinstance(value, int):
                return '#' + str(value)

            raise ValueError(f'Unsupported type: {type(value)}')

        if sudo_user is None:
            return None

        if isinstance(sudo_user, LDAP.Flags):
            return sudo_user

        if not isinstance(sudo_user, list):
            return [_get_value(sudo_user)]

        out = []
        for value in sudo_user:
            out.append(_get_value(value))

        return out

    def __sudo_group(self, sudo_group: None | LDAP.Flags | str | LDAPGroup | list[str | LDAPGroup]) -> list[str]:
        def _get_value(value: str | LDAPGroup):
            if isinstance(value, self.role._group_cls):
                return value.name

            if isinstance(value, str):
                return value

            if isinstance(value, int):
                return '#' + str(value)

            raise ValueError(f'Unsupported type: {type(value)}')

        if sudo_group is None:
            return None

        if isinstance(sudo_group, LDAP.Flags):
            return sudo_group

        if not isinstance(sudo_group, list):
            return [_get_value(sudo_group)]

        out = []
        for value in sudo_group:
            out.append(_get_value(value))

        return out


class LDAPAutomount(object):
    """
    LDAP automount management.
    """

    class Schema(Enum):
        '''
        LDAP automount schema.
        '''

        RFC2307 = 'rfc2307',
        RFC2307bis = 'rfc2307bis',
        AD = 'ad',

    def __init__(self, role: LDAP) -> None:
        """
        :param role: LDAP role object.
        :type role: LDAP
        """
        self.__role = role
        self.__schema = self.Schema.RFC2307

    def map(self, name: str, basedn: LDAPObject | str | None = 'ou=autofs') -> LDAPAutomountMap:
        """
        Get automount map object.

        :param name: Automount map name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=autofs``
        :type basedn: LDAPObject | str | None, optional
        :return: New automount map object.
        :rtype: LDAPAutomountMap
        """
        return LDAPAutomountMap(self.__role, name, basedn, schema=self.__schema)

    def key(self, name: str, map: LDAPAutomountMap) -> LDAPAutomountKey:
        """
        Get automount key object.

        :param name: Automount key name.
        :type name: str
        :param map: Automount map that is a parent to this key.
        :type map: LDAPAutomountMap
        :return: New automount key object.
        :rtype: LDAPAutomountKey
        """
        return LDAPAutomountKey(self.__role, name, map, schema=self.__schema)

    def set_schema(self, schema: 'LDAPAutomount.Schema'):
        self.__schema = schema


class LDAPAutomountMap(LDAPObject):
    """
    LDAP automount map management.
    """

    def __init__(
        self,
        role: LDAP,
        name: str,
        basedn: LDAPObject | str | None = 'ou=autofs',
        *,
        schema: LDAPAutomount.Schema = LDAPAutomount.Schema.RFC2307
    ) -> None:
        """
        :param role: LDAP role object.
        :type role: LDAP
        :param name: Automount map name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=autofs``
        :type basedn: LDAPObject | str | None, optional
        :param schema: LDAP Automount schema, defaults to ``LDAPAutomount.Schema.RFC2307``
        :type schema: LDAPAutomount.Schema
        """
        self.__schema = schema
        self.__attrs = self.__get_attrs_map(schema)
        super().__init__(role, f'{self.__attrs["rdn"]}={name}', basedn, default_ou='autofs')
        self.name = name

    def __get_attrs_map(self, schema: LDAPAutomount.Schema) -> dict[str, str]:
        if schema == LDAPAutomount.Schema.RFC2307:
            return {
                'objectClass': 'nisMap',
                'rdn': 'nisMapName',
                'automountMapName': 'nisMapName',
            }
        elif schema == LDAPAutomount.Schema.RFC2307bis:
            return {
                'objectClass': 'automountMap',
                'rdn': 'automountMapName',
                'automountMapName': 'automountMapName',
            }
        elif schema == LDAPAutomount.Schema.AD:
            return {
                'objectClass': 'nisMap',
                'rdn': 'cn',
                'automountMapName': 'nisMapName',
            }
        else:
            raise ValueError(f'Unknown schema: {schema}')

    def add(
        self,
    ) -> LDAPAutomountMap:
        """
        Create new LDAP automount map.

        :return: Self.
        :rtype: LDAPAutomountMap
        """
        attrs = {
            'objectClass': self.__attrs['objectClass'],
            self.__attrs['automountMapName']: self.name,
        }

        if self.__schema == LDAPAutomount.Schema.AD:
            attrs['cn'] = self.name

        self._add(attrs)
        return self

    def key(self, name: str) -> LDAPAutomountKey:
        """
        Get automount key object for this map.

        :param name: Automount key name.
        :type name: str
        :return: New automount key object.
        :rtype: LDAPAutomountKey
        """
        return LDAPAutomountKey(self.role, name, self, schema=self.__schema)


class LDAPAutomountKey(LDAPObject):
    """
    LDAP automount key management.
    """

    def __init__(
        self,
        role: LDAP,
        name: str,
        map: LDAPAutomountMap,
        *,
        schema: LDAPAutomount.Schema = LDAPAutomount.Schema.RFC2307
    ) -> None:
        """
        :param role: LDAP role object.
        :type role: LDAP
        :param name: Automount key name.
        :type name: str
        :param map: Automount map that is a parent to this key.
        :type map: LDAPAutomountMap
        :param schema: LDAP Automount schema, defaults to ``LDAPAutomount.Schema.RFC2307``
        :type schema: LDAPAutomount.Schema
        """
        self.__schema = schema
        self.__attrs = self.__get_attrs_map(schema)
        super().__init__(role, f'{self.__attrs["rdn"]}={name}', map)
        self.name = name
        self.map = map
        self.info = ''

    def __get_attrs_map(self, schema: LDAPAutomount.Schema) -> dict[str, str]:
        if schema == LDAPAutomount.Schema.RFC2307:
            return {
                'objectClass': 'nisObject',
                'rdn': 'cn',
                'automountKey': 'cn',
                'automountInformation': 'nisMapEntry',
            }
        elif schema == LDAPAutomount.Schema.RFC2307bis:
            return {
                'objectClass': 'automount',
                'rdn': 'automountKey',
                'automountKey': 'automountKey',
                'automountInformation': 'automountInformation',
            }
        elif schema == LDAPAutomount.Schema.AD:
            return {
                'objectClass': 'nisObject',
                'rdn': 'cn',
                'automountKey': 'cn',
                'automountInformation': 'nisMapEntry',
            }
        else:
            raise ValueError(f'Unknown schema: {schema}')

    def add(
        self,
        *,
        info: str | NFSExport | LDAPAutomountMap
    ) -> LDAPAutomountKey:
        """
        Create new LDAP automount key.

        :param info: Automount information.
        :type info: str | NFSExport | LDAPAutomountMap
        :return: Self.
        :rtype: LDAPAutomountKey
        """
        info = self.__get_info(info)
        attrs = {
            'objectClass': self.__attrs['objectClass'],
            self.__attrs['automountKey']: self.name,
            self.__attrs['automountInformation']: info,
        }

        if self.__schema in [LDAPAutomount.Schema.RFC2307, LDAPAutomount.Schema.AD]:
            attrs['nisMapName'] = self.map.name

        self._add(attrs)
        self.info = info
        return self

    def modify(
        self,
        *,
        info: str | NFSExport | LDAPAutomountMap | LDAP.Flags | None = None,
    ) -> LDAPAutomountKey:
        """
        Modify existing LDAP automount key.

        :param info: Automount information, defaults to ``None``
        :type info: str | NFSExport | LDAPAutomountMap | LDAP.Flags | None
        :return: Self.
        :rtype: LDAPAutomountKey
        """
        info = self.__get_info(info)
        attrs = {
            self.__attrs['automountInformation']: info,
        }

        self._set(attrs)
        self.info = info if info != LDAP.Flags.DELETE else ''
        return self

    def dump(self) -> str:
        """
        Dump the key in the ``automount -m`` format.

        .. code-block:: text

            export1 | -fstype=nfs,rw,sync,no_root_squash nfs.test:/dev/shm/exports/export1

        You can also call ``str(key)`` instead of ``key.dump()``.

        :return: Key information in ``automount -m`` format.
        :rtype: str
        """
        return f'{self.name} | {self.info}'

    def __str__(self) -> str:
        return self.dump()

    def __get_info(self, info: str | NFSExport | LDAPAutomountMap | LDAP.Flags | None):
        if isinstance(info, NFSExport):
            return info.get()

        if isinstance(info, LDAPAutomountMap):
            return info.name

        return info
