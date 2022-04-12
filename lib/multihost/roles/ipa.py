from __future__ import annotations

from .base import BaseObject, LinuxRole


class IPA(LinuxRole):
    """
    IPA service management.
    """

    def setup(self) -> None:
        """
        Setup IPA role.

        #. backup IPA data
        #. kinit as admin
        """
        super().setup()
        self.host.backup()
        self.host.kinit()

    def teardown(self) -> None:
        """
        Teardown IPA role.

        #. restore original IPA data
        """
        self.host.restore()
        super().teardown()

    def user(self, name: str) -> IPAUser:
        """
        Get user object.

        :param name: User name.
        :type name: str
        :return: New user object.
        :rtype: IPAUser
        """
        return IPAUser(self, name)

    def group(self, name: str) -> IPAGroup:
        """
        Get group object.

        :param name: Group name.
        :type name: str
        :return: New group object.
        :rtype: IPAGroup
        """
        return IPAGroup(self, name)

    def sudorule(self, name: str) -> IPASudoRule:
        """
        Get sudo rule object.

        :param name: Sudo rule name.
        :type name: str
        :return: New sudo rule object.
        :rtype: IPASudoRule
        """
        return IPASudoRule(self, name)


class IPAObject(BaseObject):
    """
    Base IPA object class.
    """

    def __init__(self, role: IPA, command: str, name: str) -> None:
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
        return self.role.host.exec(['ipa', f'{self.command}-{op}', self.name, *args], **kwargs)

    def _add(self, attrs: dict[str, tuple[BaseObject.cli, any]], stdin: str | None = None):
        self._exec('add', self._build_args(attrs), stdin=stdin)

    def _modify(self, attrs: dict[str, tuple[BaseObject.cli, any]], stdin: str | None = None):
        self._exec('mod', self._build_args(attrs), stdin=stdin)

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

        self._add(attrs, stdin=password)
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

        self._modify(attrs, stdin=password)
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


class IPASudoRule(IPAObject):
    """
    IPA sudo rule management.
    """

    def __init__(self, role: IPA, name: str) -> None:
        """
        :param role: IPA role object.
        :type role: IPA
        :param name: Sudo rule name.
        :type name: str
        """
        super().__init__(role, 'sudorule', name)

    def add(
        self,
        *,
        user: str | IPAUser | IPAGroup | list[str | IPAUser | IPAGroup] | None = None,
        host: str | list[str] | None = None,
        command: str | list[str] | None = None,
        option: str | list[str] | None = None,
        runasuser: str | IPAUser | IPAGroup | list[str | IPAUser | IPAGroup] | None = None,
        runasgroup: str | IPAGroup | list[str | IPAGroup] | None = None,
        order: int | None = None,
        nopasswd: bool | None = None
    ) -> IPASudoRule:
        """
        Create new sudo rule.

        :param user: sudoUser attribute, defaults to None
        :type user: str | IPAUser | IPAGroup | list[str  |  IPAUser  |  IPAGroup] | None, optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str] | None, optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str] | None, optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None
        :type runasuser: str | IPAUser | IPAGroup | list[str  |  IPAUser  |  IPAGroup] | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: str | IPAGroup | list[str  |  IPAGroup] | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: _description_
        :rtype: IPASudoRule
        """
        # Prepare data
        (allow_commands, deny_commands, cmdcat) = self.__get_commands(command)
        (hosts, hostcat) = self.__get_hosts(host)
        (users, groups, usercat) = self.__get_users_and_groups(user)
        options = self._to_string_list(option)
        (runasuser_users, runasuser_groups, runasusercat) = self.__get_run_as_user(runasuser)
        (runasgroup_groups, runasgroupcat) = self.__get_run_as_group(runasgroup)

        if nopasswd is True:
            options = self._include_attr_value(options, '!authenticate')
        elif nopasswd is False:
            options = self._include_attr_value(options, 'authenticate')

        # Add commands
        for cmd in allow_commands + deny_commands:
            self.role.host.exec(f'ipa sudocmd-find "{cmd}" || ipa sudocmd-add "{cmd}"')

        # Add command group for commands allowed by this rule
        self.role.host.exec(f'ipa sudocmdgroup-add "{self.name}_allow"')
        args = self.__args_from_list('sudocmds', allow_commands)
        self.__exec_with_args('sudocmdgroup-add-member', f'{self.name}_allow', args)

        # Add command groups for commands denied by this rule
        self.role.host.exec(f'ipa sudocmdgroup-add "{self.name}_deny"')
        args = self.__args_from_list('sudocmds', deny_commands)
        self.__exec_with_args('sudocmdgroup-add-member', f'{self.name}_deny', args)

        # Add sudo rule
        args = '' if order is None else f'"{order}"'
        args += f' {cmdcat} {usercat} {hostcat} {runasusercat} {runasgroupcat}'
        self.role.host.exec(f'ipa sudorule-add "{self.name}" {args}')

        # Allow and deny commands through command groups
        self.role.host.exec(f'ipa sudorule-add-allow-command "{self.name}" "--sudocmdgroups={self.name}_allow"')
        self.role.host.exec(f'ipa sudorule-add-deny-command "{self.name}" "--sudocmdgroups={self.name}_deny"')

        # Add hosts
        args = self.__args_from_list('hosts', hosts)
        self.__exec_with_args('sudorule-add-host', self.name, args)

        # Add options
        args = self.__args_from_list('option', hosts)
        self.__exec_with_args('sudorule-add-option', self.name, args)

        # Add run as user
        args_users = self.__args_from_list('users', runasuser_users)
        args_groups = self.__args_from_list('groups', runasuser_groups)
        self.__exec_with_args('sudorule-add-runasuser', self.name, args_users + args_groups)

        # Add run as group
        args = self.__args_from_list('groups', runasgroup_groups)
        self.__exec_with_args('sudorule-add-runasgroup', self.name, args_groups)

        # Add users and groups
        args_users = self.__args_from_list('users', users)
        args_groups = self.__args_from_list('groups', groups)
        self.__exec_with_args('sudorule-add-user', self.name, args_users + args_groups)

        return self

    def modify(
        self,
        *,
        user: str | IPAUser | IPAGroup | list[str | IPAUser | IPAGroup] | None = None,
        host: str | list[str] | None = None,
        command: str | list[str] | None = None,
        option: str | list[str] | None = None,
        runasuser: str | IPAUser | IPAGroup | list[str | IPAUser | IPAGroup] | None = None,
        runasgroup: str | IPAGroup | list[str | IPAGroup] | None = None,
        order: int | None = None,
        nopasswd: bool | None = None
    ) -> IPASudoRule:
        """
        Create new sudo rule.

        :param user: sudoUser attribute, defaults to None
        :type user: str | IPAUser | IPAGroup | list[str  |  IPAUser  |  IPAGroup] | None, optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str] | None, optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str] | None, optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None
        :type runasuser: str | IPAUser | IPAGroup | list[str  |  IPAUser  |  IPAGroup] | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: str | IPAGroup | list[str  |  IPAGroup] | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: _description_
        :rtype: IPASudoRule
        """
        self.delete()
        self.add(user=user, host=host, command=command, option=option,
                 runasuser=runasuser, runasgroup=runasgroup, order=order,
                 nopasswd=nopasswd)

        return self

    def delete(self) -> None:
        """
        Delete sudo rule from IPA.
        """
        self.role.host.exec(f'ipa sudorule-del "{self.name}"')
        self.role.host.exec(f'ipa sudocmdgroup-del "{self.name}_allow"')
        self.role.host.exec(f'ipa sudocmdgroup-del "{self.name}_deny"')

    def __get_commands(self, value: str | list[str]) -> tuple[list[str], list[str], str]:
        allow_commands = []
        deny_commands = []
        category = ''
        for cmd in self._to_string_list(value):
            if cmd == 'ALL':
                category = '--cmdcat=all'
                continue

            if cmd.startswith('!'):
                deny_commands.append(cmd[1:])
                continue

            allow_commands.append(cmd)

        return (allow_commands, deny_commands, category)

    def __get_hosts(self, value: str | list[str]) -> tuple[list[str], str]:
        hosts = []
        category = ''
        for host in self._to_string_list(value):
            if host == 'ALL':
                category = '--hostcat=all'
                continue

            hosts.append(host)

        return (hosts, category)

    def __get_users_and_groups(
        self,
        value: str | IPAUser | IPAGroup | list[str | IPAUser | IPAGroup]
    ) -> tuple[list[str], list[str], str]:
        users = []
        groups = []
        category = ''
        for item in self._to_list(value):
            if isinstance(item, str) and item == 'ALL':
                category = '--usercat=all'
                continue

            if isinstance(item, IPAGroup):
                groups.append(item.name)
                continue

            if isinstance(item, str) and item.startswith('%'):
                groups.append(item[1:])
                continue

            if isinstance(item, IPAUser):
                users.append(item.name)
                continue

            if isinstance(item, str):
                users.append(item)
                continue

            raise ValueError(f'Unsupported type: {type(item)}')

        return (users, groups, category)

    def __get_run_as_user(
        self,
        value: str | IPAUser | IPAGroup | list[str | IPAUser | IPAGroup]
    ) -> tuple[list[str], list[str], str]:
        (users, groups, category) = self.__get_users_and_groups(value)
        if category:
            category = '--runasusercat=all'

        return (users, groups, category)

    def __get_run_as_group(
        self,
        value: str | IPAGroup | list[str | IPAGroup]
    ) -> tuple[list[str], str]:
        groups = []
        category = ''
        for item in self._to_list(value):
            if isinstance(item, str) and item == 'ALL':
                category = '--runasgroupcat=all'
                continue

            if isinstance(item, IPAGroup):
                groups.append(item.name)
                continue

            if isinstance(item, str):
                groups.append(item)
                continue

            raise ValueError(f'Unsupported type: {type(item)}')

        return (groups, category)

    def __args_from_list(self, option: str, value: list[str]) -> str:
        if not value:
            return ''

        args = ''
        for cmd in value:
            args += f' "--{option}={cmd}"'

        return args

    def __exec_with_args(self, cmd: str, name: str, args: str) -> None:
        if args:
            self.role.host.exec(f'ipa {cmd} "{name}" {args}')
