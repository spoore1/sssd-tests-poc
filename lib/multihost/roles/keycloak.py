from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..host import IPAHost
from .base import BaseObject, LinuxRole

if TYPE_CHECKING:
    from ..multihost import Multihost


class Keycloak(LinuxRole[KeycloakHost]):
    """
    IPA service management.
    """

    def __init__(self, mh: Multihost, role: str, host: KeycloakHost) -> None:
        super().__init__(mh, role, host, user_cls=KeycloakUser, group_cls=KeycloakGroup)


    def setup(self) -> None:
        """
        Make sure we have admin's TGT so we can run ipa cli commands.
        """
        super().setup()
        self.host.kinit()

    def user(self, name: str) -> KeycloakUser:
        """
        Get user object.

        :param name: User name.
        :type name: str
        :return: New user object.
        :rtype: IPAUser
        """
        return KeycloakUser(self, name)

    def group(self, name: str) -> KeycloakGroup:
        """
        Get group object.

        :param name: Group name.
        :type name: str
        :return: New group object.
        :rtype: IPAGroup
        """
        return KeycloakGroup(self, name)


class KeycloakObject(BaseObject):
    """
    Base IPA object class.
    """

    def __init__(self, role: Keycloak, command: str, name: str) -> None:
        """
        :param role: IPA role object.
        :type role: IPA
        :param command: IPA command group.
        :type command: str
        :param name: Object name.
        :type name: str
        """
        super().__init__()
        self.role = role
        self.command = command
        self.name = name

    def _exec(self, op: str, args: list[str] = list(), **kwargs) -> None:
        return self.role.host.ssh.exec(['ipa', f'{self.command}-{op}', self.name, *args], **kwargs)

    def _add(self, attrs: dict[str, tuple[BaseObject.cli, Any]] = dict(), input: str | None = None):
        self._exec('add', self._build_args(attrs), input=input)

    def _modify(self, attrs: dict[str, tuple[BaseObject.cli, Any]], input: str | None = None):
        self._exec('mod', self._build_args(attrs), input=input)

    def delete(self) -> None:
        """
        Delete object from IPA.
        """
        self._exec('del')

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get IPA object attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        cmd = self._exec('show', ['--all', '--raw'])

        # Remove first line that contains the object name and not attribute
        return self._parse_attrs(cmd.stdout_lines[1:], attrs)


class IPAUser(IPAObject):
    """
    IPA user management.
    """

    def __init__(self, role: IPA, name: str) -> None:
        """
        :param role: IPA role object.
        :type role: IPA
        :param name: User name.
        :type name: str
        """
        super().__init__(role, 'user', name)

    def add(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str | None = 'Secret123',
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
        require_password_reset: bool = False
    ) -> IPAUser:
        """
        Create new IPA user.

        Parameters that are not set are ignored.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param password: Password, defaults to 'Secret123'
        :type password: str | None, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :param require_password_reset: Require password reset on first login, defaults to False
        :type require_password_reset: bool, optional
        :return: Self.
        :rtype: IPAUser
        """
        attrs = {
            'first': (self.cli.VALUE, self.name),
            'last': (self.cli.VALUE, self.name),
            'uid': (self.cli.VALUE, uid),
            'gidnumber': (self.cli.VALUE, gid),
            'homedir': (self.cli.VALUE, home),
            'gecos': (self.cli.VALUE, gecos),
            'shell': (self.cli.VALUE, shell),
            'password': (self.cli.SWITCH, True) if password is not None else None,
        }

        if not require_password_reset:
            attrs['password-expiration'] = (self.cli.VALUE, '20380805120000Z')

        self._add(attrs, input=password)
        return self

    def modify(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str | None = None,
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
    ) -> IPAUser:
        """
        Modify existing IPA user.

        Parameters that are not set are ignored.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param password: Password, defaults to 'Secret123'
        :type password: str | None, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :return: Self.
        :rtype: IPAUser
        """
        attrs = {
            'uid': (self.cli.VALUE, uid),
            'gidnumber': (self.cli.VALUE, gid),
            'homedir': (self.cli.VALUE, home),
            'gecos': (self.cli.VALUE, gecos),
            'shell': (self.cli.VALUE, shell),
            'password': (self.cli.SWITCH, True) if password is not None else None,
        }

        self._modify(attrs, input=password)
        return self


class IPAGroup(IPAObject):
    """
    IPA group management.
    """

    def __init__(self, role: IPA, name: str) -> None:
        """
        :param role: IPA role object.
        :type role: IPA
        :param name: Group name.
        :type name: str
        """
        super().__init__(role, 'group', name)

    def add(
        self,
        *,
        gid: int | None = None,
        description: str | None = None,
        nonposix: bool = False,
        external: bool = False,
    ) -> IPAGroup:
        """
        Create new IPA group.

        Parameters that are not set are ignored.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :param description: Description, defaults to None
        :type description: str | None, optional
        :param nonposix: Group is non-posix group, defaults to False
        :type nonposix: bool, optional
        :param external: Group is external group, defaults to False
        :type external: bool, optional
        :return: Self.
        :rtype: IPAGroup
        """
        attrs = {
            'gid': (self.cli.VALUE, gid),
            'desc': (self.cli.VALUE, description),
            'nonposix': (self.cli.SWITCH, True) if nonposix else None,
            'external': (self.cli.SWITCH, True) if external else None,
        }

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        gid: int | None = None,
        description: str | None = None,
    ) -> IPAGroup:
        """
        Modify existing IPA group.

        Parameters that are not set are ignored.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :param description: Description, defaults to None
        :type description: str | None, optional
        :return: Self.
        :rtype: IPAGroup
        """
        attrs = {
            'gid': (self.cli.VALUE, gid),
            'desc': (self.cli.VALUE, description),
        }

        self._modify(attrs)
        return self

    def add_member(self, member: IPAUser | IPAGroup) -> IPAGroup:
        """
        Add group member.

        :param member: User or group to add as a member.
        :type member: IPAUser | IPAGroup
        :return: Self.
        :rtype: IPAGroup
        """
        return self.add_members([member])

    def add_members(self, members: list[IPAUser | IPAGroup]) -> IPAGroup:
        """
        Add multiple group members.

        :param member: List of users or groups to add as members.
        :type member: list[IPAUser | IPAGroup]
        :return: Self.
        :rtype: IPAGroup
        """
        self._exec('add-member', self.__get_member_args(members))
        return self

    def remove_member(self, member: IPAUser | IPAGroup) -> IPAGroup:
        """
        Remove group member.

        :param member: User or group to remove from the group.
        :type member: IPAUser | IPAGroup
        :return: Self.
        :rtype: IPAGroup
        """
        return self.remove_members([member])

    def remove_members(self, members: list[IPAUser | IPAGroup]) -> IPAGroup:
        """
        Remove multiple group members.

        :param member: List of users or groups to remove from the group.
        :type member: list[IPAUser | IPAGroup]
        :return: Self.
        :rtype: IPAGroup
        """
        self._exec('remove-member', self.__get_member_args(members))
        return self

    def __get_member_args(self, members: list[IPAUser | IPAGroup]) -> list[str]:
        users = [x for item in members if isinstance(item, IPAUser) for x in ('--users', item.name)]
        groups = [x for item in members if isinstance(item, IPAGroup) for x in ('--groups', item.name)]
        return [*users, *groups]