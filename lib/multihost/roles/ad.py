from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

from ..command import RemoteCommandResult
from ..host import ADHost
from ..utils.ldap import HostLDAP
from .base import BaseObject, WindowsRole
from .nfs import NFSExport

if TYPE_CHECKING:
    from ..multihost import Multihost


class AD(WindowsRole):
    """
    AD service management.
    """

    def __init__(self, mh: Multihost, role: str, host: ADHost) -> None:
        super().__init__(mh, role, host, user_cls=ADUser, group_cls=ADGroup)
        self.ldap: HostLDAP = HostLDAP(host)
        self.auto_ou: dict[str, bool] = {}

        self.automount: ADAutomount = ADAutomount(self)
        """
        Provides API to manipulate automount objects.
        """

    def setup(self) -> None:
        """
        Setup AD role.

        #. backup AD data
        """
        super().setup()
        self.host.backup()

    def teardown(self) -> None:
        """
        Teardown AD role.

        #. restore original AD data
        """
        self.host.restore()
        super().teardown()

    def user(self, name: str, basedn: ADObject | str | None = 'cn=users') -> ADUser:
        """
        Get user object.

        :param name: User name.
        :type name: str
        :param basedn: Base dn, defaults to ``cn=users``
        :type basedn: ADObject | str | None, optional
        :return: New user object.
        :rtype: ADUser
        """
        return ADUser(self, name, basedn)

    def group(self, name: str, basedn: ADObject | str | None = 'cn=users') -> ADGroup:
        """
        Get group object.

        :param name: Group name.
        :type name: str
        :param basedn: Base dn, defaults to ``cn=users``
        :type basedn: ADObject | str | None, optional
        :return: New group object.
        :rtype: ADGroup
        """
        return ADGroup(self, name, basedn)

    def ou(self, name: str, basedn: ADObject | str | None = None) -> ADOrganizationalUnit:
        """
        Get organizational unit object.

        :param name: Unit name.
        :type name: str
        :param basedn: Base dn, defaults to None
        :type basedn: ADObject | str | None, optional
        :return: New organizational unit object.
        :rtype: ADOrganizationalUnit
        """
        return ADOrganizationalUnit(self, name, basedn)

    def sudorule(self, name: str, basedn: ADObject | str | None = 'ou=sudoers') -> ADSudoRule:
        """
        Get sudo rule object.

        :param name: Rule name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=sudoers``
        :type basedn: ADObject | str | None, optional
        :return: New sudo rule object.
        :rtype: ADSudoRule
        """

        return ADSudoRule(self, name, basedn)


class ADObject(BaseObject):
    """
    Base AD object class.
    """

    def __init__(
        self,
        role: AD,
        command_group: str,
        name: str,
        rdn: str,
        basedn: ADObject | str | None = None,
        default_ou: str | None = None
    ) -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param command_group: AD command group.
        :type command_group: str
        :param name: Object name.
        :type name: str
        :param rdn: Relative distinguished name.
        :type rdn: str
        :param basedn: Base dn, defaults to None
        :type basedn: ADObject | str | None, optional
        :param default_ou: Name of default organizational unit that is automatically
                           created if basedn is set to ou=$default_ou, defaults to None.
        :type default_ou: str | None, optional
        """
        super().__init__(cli_prefix='-')

        self.role = role
        self.command_group = command_group
        self.name = name
        self.rdn = rdn
        self.basedn = basedn
        self.dn = self._dn(rdn, basedn)
        self.path = self._path(basedn)
        self.default_ou = default_ou
        self._identity = {'Identity': (self.cli.VALUE, self.dn)}

        self.__create_default_ou(basedn, self.default_ou)

    def __create_default_ou(self, basedn: ADObject | str | None, default_ou: str | None) -> None:
        if basedn is None or not isinstance(basedn, str):
            return

        if basedn.lower() != f'ou={default_ou}' or default_ou in self.role.auto_ou:
            return

        self.role.ou(default_ou).add()
        self.role.auto_ou[default_ou] = True

    def _dn(self, rdn: str, basedn: ADObject | str | None = None) -> str:
        """
        Get distinguished name of an object.

        :param rdn: Relative DN.
        :type rdn: str
        :param basedn: Base DN, defaults to None
        :type basedn: ADObject | str | None, optional
        :return: Distinguished name combined from rdn+dn+naming-context.
        :rtype: str
        """
        if isinstance(basedn, ADObject):
            return f'{rdn},{basedn.dn}'

        return self.role.ldap.dn(rdn, basedn)

    def _path(self, basedn: ADObject | str | None = None) -> str:
        """
        Get object LDAP path.

        :param basedn: Base DN, defaults to None
        :type basedn: ADObject | str | None, optional
        :return: Distinguished name of the parent container combined from basedn+naming-context.
        :rtype: str
        """
        if isinstance(basedn, ADObject):
            return basedn.dn

        if not basedn:
            return self.role.host.naming_context

        return f'{basedn},{self.role.host.naming_context}'

    def _exec(self, op: str, args: list[str] | str = list(), **kwargs) -> RemoteCommandResult:
        if isinstance(args, list):
            args = ' '.join(args)
        elif args is None:
            args = ''

        return self.role.host.exec(textwrap.dedent(f'''
            Import-Module ActiveDirectory
            {op}-AD{self.command_group} {args}
        ''').strip(), **kwargs)

    def _add(self, attrs: dict[str, tuple[BaseObject.cli, any]]) -> None:
        self._exec('New', self._build_args(attrs))

    def _modify(self, attrs: dict[str, tuple[BaseObject.cli, any]]) -> None:
        self._exec('Set', self._build_args(attrs))

    def delete(self) -> None:
        """
        Delete object from AD.
        """
        args = {
            'Confirm': (self.cli.SWITCH, False),
            **self._identity,
        }
        self._exec('Remove', self._build_args(args))

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get AD object attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        cmd = self._exec('Get', self._build_args(self._identity))
        return self._parse_attrs(cmd.stdout_lines, attrs)

    def _attrs_to_hash(self, attrs: dict[str, any]) -> str | None:
        out = ''
        for key, value in attrs.items():
            if value is not None:
                if isinstance(value, list):
                    values = [f'"{x}"' for x in value]
                    out += f'"{key}"={",".join(values)};'
                else:
                    out += f'"{key}"="{value}";'

        if not out:
            return None

        return '@{' + out.rstrip(';') + '}'

    def _build_args(
        self,
        attrs: dict[str, tuple[BaseObject.cli, any]],
        as_script: bool = True,
        admode: bool = True
    ) -> list[str] | str:
        return super()._build_args(attrs, as_script=as_script, admode=admode)


class ADOrganizationalUnit(ADObject):
    """
    AD organizational unit management.
    """

    def __init__(self, role: AD, name: str, basedn: ADObject | str | None = None) -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Unit name.
        :type name: str
        :param basedn: Base dn, defaults to None
        :type basedn: ADObject | str | None, optional
        """
        super().__init__(role, 'OrganizationalUnit', name, f'ou={name}', basedn)

    def add(self) -> ADOrganizationalUnit:
        """
        Create new AD organizational unit.

        :return: Self.
        :rtype: ADOrganizationalUnit
        """
        attrs = {
            'Name': (self.cli.VALUE, self.name),
            'Path': (self.cli.VALUE, self.path),
            'ProtectedFromAccidentalDeletion': (self.cli.PLAIN, '$False')
        }

        self._add(attrs)
        return self


class ADUser(ADObject):
    """
    AD user management.
    """

    def __init__(self, role: AD, name: str, basedn: ADObject | str | None = 'cn=users') -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: User name.
        :type name: str
        :param basedn: Base dn, defaults to 'cn=users'
        :type basedn: ADObject | str | None, optional
        """
        # There is no automatically created default ou because cn=users already exists
        super().__init__(role, 'User', name, f'cn={name}', basedn, default_ou=None)

    def add(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str = 'Secret123',
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
    ) -> ADUser:
        """
        Create new AD user.

        Parameters that are not set are ignored.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param password: Password (cannot be None), defaults to 'Secret123'
        :type password: str, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :return: Self.
        :rtype: ADUser
        """
        unix_attrs = {
            'uid': self.name,
            'uidNumber': uid,
            'gidNumber': gid,
            'unixHomeDirectory': home,
            'gecos': gecos,
            'loginShell': shell
        }

        attrs = {
            'Name': (self.cli.VALUE, self.name),
            'AccountPassword': (self.cli.PLAIN, f'(ConvertTo-SecureString "{password}" -AsPlainText -force)'),
            'OtherAttributes': (self.cli.PLAIN, self._attrs_to_hash(unix_attrs)),
            'Enabled': (self.cli.PLAIN, '$True'),
            'Path': (self.cli.VALUE, self.path),
        }

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        uid: int | AD.Flags | None = None,
        gid: int | AD.Flags | None = None,
        home: str | AD.Flags | None = None,
        gecos: str | AD.Flags | None = None,
        shell: str | AD.Flags | None = None,
    ) -> ADUser:
        """
        Modify existing AD user.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to ``AD.Flags.DELETE``.

        :param uid: User id, defaults to None
        :type uid: int | AD.Flags | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | AD.Flags | None, optional
        :param home: Home directory, defaults to None
        :type home: str | AD.Flags | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | AD.Flags | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | AD.Flags | None, optional
        :return: Self.
        :rtype: ADUser
        """
        unix_attrs = {
            'uidNumber': uid,
            'gidNumber': gid,
            'unixHomeDirectory': home,
            'gecos': gecos,
            'loginShell': shell
        }

        clear = [key for key, value in unix_attrs.items() if value == AD.Flags.DELETE]
        replace = {key: value for key, value in unix_attrs.items() if value is not None and value != AD.Flags.DELETE}

        attrs = {
            **self._identity,
            'Replace': (self.cli.PLAIN, self._attrs_to_hash(replace)),
            'Clear': (self.cli.PLAIN, ','.join(clear) if clear else None),
        }

        self._modify(attrs)
        return self


class ADGroup(ADObject):
    """
    AD group management.
    """

    def __init__(self, role: AD, name: str, basedn: ADObject | str | None = 'cn=users') -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Group name.
        :type name: str
        :param basedn: Base dn, defaults to 'cn=users'
        :type basedn: ADObject | str | None, optional
        """
        # There is no automatically created default ou because cn=users already exists
        super().__init__(role, 'Group', name, f'cn={name}', basedn, default_ou=None)

    def add(
        self,
        *,
        gid: int | None = None,
        description: str | None = None,
        scope: str = 'Global',
        category: str = 'Security',
    ) -> ADGroup:
        """
        Create new AD group.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :param description: Description, defaults to None
        :type description: str | None, optional
        :param scope: Scope ('Global', 'Universal', 'DomainLocal'), defaults to 'Global'
        :type scope: str, optional
        :param category: Category ('Distribution', 'Security'), defaults to 'Security'
        :type category: str, optional
        :return: Self.
        :rtype: ADGroup
        """
        unix_attrs = {
            'gidNumber': gid,
            'description': description,
        }

        attrs = {
            'Name': (self.cli.VALUE, self.name),
            'GroupScope': (self.cli.VALUE, scope),
            'GroupCategory': (self.cli.VALUE, category),
            'OtherAttributes': (self.cli.PLAIN, self._attrs_to_hash(unix_attrs)),
            'Path': (self.cli.VALUE, self.path),
        }

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        gid: int | AD.Flags | None = None,
        description: str | AD.Flags | None = None,
    ) -> ADUser:
        """
        Modify existing AD group.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to ``AD.Flags.DELETE``.

        :param gid: Group id, defaults to None
        :type gid: int | AD.Flags | None, optional
        :param description: Description, defaults to None
        :type description: str | AD.Flags | None, optional
        :return: Self.
        :rtype: ADUser
        """
        unix_attrs = {
            'gidNumber': gid,
            'description': description,
        }

        clear = [key for key, value in unix_attrs.items() if value == AD.Flags.DELETE]
        replace = {key: value for key, value in unix_attrs.items() if value is not None and value != AD.Flags.DELETE}

        attrs = {
            **self._identity,
            'Replace': (self.cli.PLAIN, self._attrs_to_hash(replace)),
            'Clear': (self.cli.PLAIN, ','.join(clear) if clear else None),
        }

        self._modify(attrs)
        return self

    def add_member(self, member: ADUser | ADGroup) -> ADGroup:
        """
        Add group member.

        :param member: User or group to add as a member.
        :type member: ADUser | ADGroup
        :return: Self.
        :rtype: ADGroup
        """
        return self.add_members([member])

    def add_members(self, members: list[ADUser | ADGroup]) -> ADGroup:
        """
        Add multiple group members.

        :param member: List of users or groups to add as members.
        :type member: list[ADUser | ADGroup]
        :return: Self.
        :rtype: ADGroup
        """
        self.role.host.exec(textwrap.dedent(f'''
            Import-Module ActiveDirectory
            Add-ADGroupMember -Identity '{self.dn}' -Members {self.__get_members(members)}
        ''').strip())
        return self

    def remove_member(self, member: ADUser | ADGroup) -> ADGroup:
        """
        Remove group member.

        :param member: User or group to remove from the group.
        :type member: ADUser | ADGroup
        :return: Self.
        :rtype: ADGroup
        """
        return self.remove_members([member])

    def remove_members(self, members: list[ADUser | ADGroup]) -> ADGroup:
        """
        Remove multiple group members.

        :param member: List of users or groups to remove from the group.
        :type member: list[ADUser | ADGroup]
        :return: Self.
        :rtype: ADGroup
        """
        self.role.host.exec(textwrap.dedent(f'''
            Import-Module ActiveDirectory
            Remove-ADGroupMember -Confirm:$False -Identity '{self.dn}' -Members {self.__get_members(members)}
        ''').strip())
        return self

    def __get_members(self, members: list[ADUser | ADGroup]) -> str:
        return ','.join([f'"{x.dn}"' for x in members])


class ADSudoRule(ADObject):
    """
    AD sudo rule management.
    """

    def __init__(
        self,
        role: AD,
        name: str,
        basedn: ADObject | str | None = 'ou=sudoers',
    ) -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Sudo rule name.
        :type name: str
        :param basedn: Base dn, defaults to None
        :type basedn: ADObject | str | None, optional
        """
        super().__init__(role, 'Object', name, f'cn={name}', basedn, default_ou='sudoers')

    def add(
        self,
        *,
        user: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup] | None = None,
        host: str | list[str] | None = None,
        command: str | list[str] | None = None,
        option: str | list[str] | None = None,
        runasuser: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup] | None = None,
        runasgroup: int | str | ADGroup | list[int | str | ADGroup] | None = None,
        notbefore: str | list[str] | None = None,
        notafter: str | list[str] | None = None,
        order: int | list[int] | None = None,
        nopasswd: bool | None = None
    ) -> ADSudoRule:
        """
        Create new sudo rule.

        :param user: sudoUser attribute, defaults to None
        :type user: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup], optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str], optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str], optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None
        :type runasuser: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup] | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: int | str | ADGroup | list[int | str | ADGroup] | None, optional
        :param notbefore: sudoNotBefore attribute, defaults to None
        :type notbefore: str | list[str] | None, optional
        :param notafter: sudoNotAfter attribute, defaults to None
        :type notafter: str | list[str] | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | list[int] | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: Self.
        :rtype: ADSudoRule
        """
        attrs = {
            'objectClass': 'sudoRole',
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

        args = {
            'Name': (self.cli.VALUE, self.name),
            'Type': (self.cli.VALUE, 'sudoRole'),
            'OtherAttributes': (self.cli.PLAIN, self._attrs_to_hash(attrs)),
            'Path': (self.cli.VALUE, self.path),
        }

        self._add(args)
        return self

    def modify(
        self,
        *,
        user: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup] | AD.Flags | None = None,
        host: str | list[str] | AD.Flags | None = None,
        command: str | list[str] | AD.Flags | None = None,
        option: str | list[str] | AD.Flags | None = None,
        runasuser: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup] | AD.Flags | None = None,
        runasgroup: int | str | ADGroup | list[int | str | ADGroup] | AD.Flags | None = None,
        notbefore: str | list[str] | AD.Flags | None = None,
        notafter: str | list[str] | AD.Flags | None = None,
        order: int | list[int] | AD.Flags | None = None,
        nopasswd: bool | None = None
    ) -> ADSudoRule:
        """
        Modify existing sudo rule.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to ``AD.Flags.DELETE``.

        :param user: sudoUser attribute, defaults to None
        :type user: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup]
          | AD.Flags | None, optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str] | AD.Flags | None, optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str] | AD.Flags | None, optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | AD.Flags | None, optional
        :param runasuser: sudoRunAsUsere attribute, defaults to None
        :type runasuser: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup]
          | AD.Flags | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: int | str | ADGroup | list[int | str | ADGroup] | AD.Flags | None, optional
        :param notbefore: sudoNotBefore attribute, defaults to None
        :type notbefore: str | list[str] | AD.Flags | None, optional
        :param notafter: sudoNotAfter attribute, defaults to None
        :type notafter: str | list[str] | AD.Flags | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | list[int] | AD.Flags | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: Self.
        :rtype: ADSudoRule
        """
        attrs = {
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

        clear = [key for key, value in attrs.items() if value == AD.Flags.DELETE]
        replace = {key: value for key, value in attrs.items() if value is not None and value != AD.Flags.DELETE}

        attrs = {
            **self._identity,
            'Replace': (self.cli.PLAIN, self._attrs_to_hash(replace)),
            'Clear': (self.cli.PLAIN, ','.join(clear) if clear else None),
        }

        self._modify(attrs)
        return self

    def __sudo_user(
        self,
        sudo_user: None | AD.Flags | str | ADUser | ADGroup | list[str | ADUser | ADGroup]
    ) -> list[str]:
        def _get_value(value: str | ADUser | ADGroup):
            if isinstance(value, ADUser):
                return value.name

            if isinstance(value, ADGroup):
                return '%' + value.name

            if isinstance(value, str):
                return value

            if isinstance(value, int):
                return '#' + str(value)

            raise ValueError(f'Unsupported type: {type(value)}')

        if sudo_user is None:
            return None

        if isinstance(sudo_user, AD.Flags):
            return sudo_user

        if not isinstance(sudo_user, list):
            return [_get_value(sudo_user)]

        out = []
        for value in sudo_user:
            out.append(_get_value(value))

        return out

    def __sudo_group(self, sudo_group: None | AD.Flags | str | ADGroup | list[str | ADGroup]) -> list[str]:
        def _get_value(value: str | ADGroup):
            if isinstance(value, ADGroup):
                return value.name

            if isinstance(value, str):
                return value

            if isinstance(value, int):
                return '#' + str(value)

            raise ValueError(f'Unsupported type: {type(value)}')

        if sudo_group is None:
            return None

        if isinstance(sudo_group, AD.Flags):
            return sudo_group

        if not isinstance(sudo_group, list):
            return [_get_value(sudo_group)]

        out = []
        for value in sudo_group:
            out.append(_get_value(value))

        return out


class ADAutomount(object):
    """
    AD automount management.
    """

    def __init__(self, role: AD) -> None:
        """
        :param role: AD role object.
        :type role: AD
        """
        self.__role = role

    def map(self, name: str, basedn: ADObject | str | None = 'ou=autofs') -> ADAutomountMap:
        """
        Get automount map object.

        :param name: Automount map name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=autofs``
        :type basedn: ADObject | str | None, optional
        :return: New automount map object.
        :rtype: ADAutomountMap
        """
        return ADAutomountMap(self.__role, name, basedn)

    def key(self, name: str, map: ADAutomountMap) -> ADAutomountKey:
        """
        Get automount key object.

        :param name: Automount key name.
        :type name: str
        :param map: Automount map that is a parent to this key.
        :type map: ADAutomountMap
        :return: New automount key object.
        :rtype: ADAutomountKey
        """
        return ADAutomountKey(self.__role, name, map)


class ADAutomountMap(ADObject):
    """
    AD automount map management.
    """

    def __init__(
        self,
        role: AD,
        name: str,
        basedn: ADObject | str | None = 'ou=autofs',
    ) -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Automount map name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=autofs``
        :type basedn: ADObject | str | None, optional
        """
        super().__init__(role, 'Object', name, f'cn={name}', basedn, default_ou='autofs')

    def add(
        self,
    ) -> ADAutomountMap:
        """
        Create new AD automount map.

        :return: Self.
        :rtype: ADAutomountMap
        """
        attrs = {
            'objectClass': 'nisMap',
            'cn': self.name,
            'nisMapName': self.name,
        }

        args = {
            'Name': (self.cli.VALUE, self.name),
            'Type': (self.cli.VALUE, 'nisMap'),
            'OtherAttributes': (self.cli.PLAIN, self._attrs_to_hash(attrs)),
            'Path': (self.cli.VALUE, self.path),
        }

        self._add(args)
        return self

    def key(self, name: str) -> ADAutomountKey:
        """
        Get automount key object for this map.

        :param name: Automount key name.
        :type name: str
        :return: New automount key object.
        :rtype: ADAutomountKey
        """
        return ADAutomountKey(self.role, name, self)


class ADAutomountKey(ADObject):
    """
    AD automount key management.
    """

    def __init__(
        self,
        role: AD,
        name: str,
        map: ADAutomountMap,
    ) -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Automount key name.
        :type name: str
        :param map: Automount map that is a parent to this key.
        :type map: ADAutomountMap
        """
        super().__init__(role, 'Object', name, f'cn={name}', map)
        self.map = map
        self.info = None

    def add(
        self,
        *,
        info: str | NFSExport | ADAutomountMap
    ) -> ADAutomountKey:
        """
        Create new AD automount key.

        :param info: Automount information.
        :type info: str | NFSExport | ADAutomountMap
        :return: Self.
        :rtype: ADAutomountKey
        """
        info = self.__get_info(info)
        attrs = {
            'objectClass': 'nisObject',
            'cn': self.name,
            'nisMapEntry': info,
            'nisMapName': self.map.name,
        }

        args = {
            'Name': (self.cli.VALUE, self.name),
            'Type': (self.cli.VALUE, 'nisObject'),
            'OtherAttributes': (self.cli.PLAIN, self._attrs_to_hash(attrs)),
            'Path': (self.cli.VALUE, self.path),
        }

        self._add(args)
        self.info = info
        return self

    def modify(
        self,
        *,
        info: str | NFSExport | ADAutomountMap | AD.Flags | None = None,
    ) -> ADAutomountKey:
        """
        Modify existing AD automount key.

        :param info: Automount information, defaults to ``None``
        :type info:  str | NFSExport | ADAutomountMap | AD.Flags | None
        :return: Self.
        :rtype: ADAutomountKey
        """
        info = self.__get_info(info)
        attrs = {
            'nisMapEntry': info,
        }

        clear = [key for key, value in attrs.items() if value == AD.Flags.DELETE]
        replace = {key: value for key, value in attrs.items() if value is not None and value != AD.Flags.DELETE}

        args = {
            **self._identity,
            'Replace': (self.cli.PLAIN, self._attrs_to_hash(replace)),
            'Clear': (self.cli.PLAIN, ','.join(clear) if clear else None),
        }

        self._modify(args)
        self.info = info if info != AD.Flags.DELETE else ''
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

    def __get_info(self, info: str | NFSExport | ADAutomountMap | AD.Flags | None):
        if isinstance(info, NFSExport):
            return info.get()

        if isinstance(info, ADAutomountMap):
            return info.name

        return info
