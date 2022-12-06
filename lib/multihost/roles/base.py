from __future__ import annotations

from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from lib.multihost.ssh import SSHClient

from ..host import MultihostHost
from ..ssh import SSHBashProcess
from ..utils.auth import HostAuthentication
from ..utils.authselect import HostAuthselect
from ..utils.base import MultihostUtility
from ..utils.fs import HostFileSystem
from ..utils.service import HostService
from ..utils.tools import HostTools

if TYPE_CHECKING:
    from ..multihost import Multihost

HostType = TypeVar('HostType', bound=MultihostHost)


class BaseRole(Generic[HostType]):
    """
    Base role class. Roles are the main interface to the remote hosts that can
    be directly accessed in test cases as fixtures.

    All changes to the remote host that were done through the role object API
    are automatically reverted when a test is finished.
    """

    class Flags(Enum):
        DELETE = auto()
        """
        Delete attribute when modifying object.
        """

    def __init__(
        self,
        mh: Multihost,
        role: str,
        host: HostType,
        user_cls: type = None,
        group_cls: type = None
    ) -> None:
        self.mh: Multihost = mh
        self.role: str = role
        self.host: HostType = host

        # This supports code sharing between native LDAP and AD and Samba roles.
        # AD and Samba has specific user and group objects, everything else is
        # the same as in native LDAP so there is plenty of space to share code.
        # However some areas need to distinguish between users and groups that
        # are passed as parameters so we need to check that the value is
        # instance of given class.
        self._user_cls = user_cls
        self._group_cls = group_cls

    def setup(self) -> None:
        """
        Setup all :class:`lib.multihost.utils.base.MultihostUtility` objects
        that are attributes of this class.

        :meta private:
        """
        MultihostUtility.SetupUtilityAttributes(self)

    def teardown(self) -> None:
        """
        Teardown all :class:`lib.multihost.utils.base.MultihostUtility` objects
        that are attributes of this class.

        :meta private:
        """
        MultihostUtility.TeardownUtilityAttributes(self)

    def collect_artifacts(self) -> None:
        """
        Collect test artifacts.

        :meta private:
        """
        pass

    def ssh(self, user: str, password: str, *, shell=SSHBashProcess) -> SSHClient:
        """
        Open SSH connection to the host as given user.

        :param user: Username.
        :type user: str
        :param password: User password.
        :type password: str
        :param shell: Shell that will run the commands, defaults to SSHBashProcess
        :type shell: str, optional
        :return: SSH client connection.
        :rtype: SSHClient
        """
        return SSHClient(self.host.hostname, user=user, password=password, shell=shell, logger=self.mh.logger)


class BaseObject(object):
    """
    Base class for service object management like users and groups. This class
    provide helper functions to parse output and build command line arguments.
    """

    class cli(Enum):
        """
        Command line parameter types.
        """

        PLAIN = auto()
        """
        Use plain parameter value without any modification.
        """

        VALUE = auto()
        """
        Use parameter value but enclose it in quotes in script mode.
        """

        SWITCH = auto()
        """
        Parameter is a switch which is enabled if value is True.
        """

        POSITIONAL = auto()
        """
        Parameter is a positional argument.
        """

    def __init__(self, cli_prefix: str = '--') -> None:
        """
        :param cli_prefix: Command line option prefix, defaults to '--'
        :type cli_prefix: str, optional
        """
        self._cli_prefix = cli_prefix

    def _build_args(
        self,
        attrs: dict[str, tuple[BaseObject.cli, Any]],
        as_script: bool = False,
        admode: bool = False
    ) -> list[str] | str:
        """
        Build command line arguments.

        Parameters are passed in ``attrs`` which is a dictionary. The key is
        name of the command line argument and the value is a tuple of ``(type,
        value)``. The value is converted to string. If no value is given, that
        is if ``value`` is ``None``, then it is omitted.

        .. code-block:: python
            :caption: Example usage

            attrs = {
                'uid': (self.cli.VALUE, uid),
                'password': (self.cli.SWITCH, True) if password is not None else None,
                ...
            }

            args = self._build_args(attrs)

        :param attrs: Command line parameters.
        :type attrs: dict[str, tuple[BaseObject.cli, Any]]
        :param as_script: Return string instead of list of arguments, defaults to False
        :type as_script: bool, optional
        :return: List of as_script (exec style) or string to be used in scripts.
        :rtype: list[str]
        """
        def encode_value(value):
            return str(value) if not as_script else f"'{value}'"

        args = []
        for key, item in attrs.items():
            if item is None:
                continue

            (type, value) = item
            if value is None:
                continue

            if type is self.cli.POSITIONAL:
                args.append(encode_value(value))
                continue

            if type is self.cli.SWITCH:
                if not admode:
                    if value is True:
                        args.append(self._cli_prefix + key)
                else:
                    # Active Directory switch style, e.g. -Confirm:$False
                    args.append(f'{self._cli_prefix}{key}:{"$True" if value else "$False"}')
                continue

            if type is self.cli.VALUE:
                args.append(self._cli_prefix + key)
                args.append(encode_value(value))
                continue

            if type is self.cli.PLAIN:
                args.append(self._cli_prefix + key)
                args.append(str(value))
                continue

            raise ValueError(f'Unknown option type: {type}')

        if as_script:
            return ' '.join(args)

        return args

    def _parse_attrs(self, lines: list[str], attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Parse LDAP attributes from output.

        :param lines: Output.
        :type lines: list[str]
        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        out = {}
        for line in lines:
            line = line.strip()
            if not line:
                continue

            (key, value) = map(lambda x: x.strip(), line.split(':', 1))
            if attrs is None or key in attrs:
                out.setdefault(key, [])
                out[key].append(value)

        return out

    def _include_attr_value(self, attr: Any | list[Any], value: Any) -> list[Any]:
        if attr is None:
            return [value]

        if not isinstance(attr, list):
            if attr != value:
                return [attr, value]

            return [attr]

        if value not in attr:
            return [*attr, value]

        return attr

    def _to_list(self, value: Any | list[Any]) -> list[Any]:
        if value is None:
            return []

        if isinstance(value, list):
            return value

        return [value]

    def _to_string_list(self, value: Any | list[Any]) -> list[str]:
        return [str(x) for x in self._to_list(value)]

    def _remove_none_from_list(self, r_list: list[Any]) -> list[Any]:
        """
        Remove all elements that are ``None`` from the list.

        :param r_list: List of all elements.
        :type r_list: list[Any]
        :return: New list with all values from the given list that are not ``None``.
        :rtype: list[Any]
        """
        return [x for x in r_list if x is not None]


class LinuxRole(BaseRole[HostType]):
    """
    Base linux role.
    """

    def __init__(
        self,
        mh: Multihost,
        role: str,
        host: HostType,
        user_cls: type = None,
        group_cls: type = None
    ) -> None:
        super().__init__(mh, role, host, user_cls=user_cls, group_cls=group_cls)

        self.authselect: HostAuthselect = HostAuthselect(host)
        """
        Manage nsswitch and PAM configuration.
        """

        self.fs: HostFileSystem = HostFileSystem(host)
        """
        File system manipulation.
        """

        self.svc: HostService = HostService(host)
        """
        Systemd service management.
        """

        self.tools: HostTools = HostTools(host)
        """
        Standard tools interface.
        """

        self.auth: HostAuthentication = HostAuthentication(host)
        """
        Authentication helpers.
        """


class WindowsRole(BaseRole[HostType]):
    """
    Base Windows role.
    """
    pass
