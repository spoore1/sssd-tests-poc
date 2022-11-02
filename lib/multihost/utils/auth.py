from __future__ import annotations

from ..host import BaseHost
from .base import MultihostUtility


class HostAuthentication(MultihostUtility):
    """
    Remote host authentication.

    Provides helpers to test authentication on remote host via su, sudo and ssh.
    """

    def __init__(self, host: BaseHost) -> None:
        """
        :param host: Remote host.
        :type host: BaseHost
        """
        super().__init__(host)

        self.su: HostSU = HostSU(host)
        """
        Interface to su command.
        """

        self.sudo: HostSudo = HostSudo(host)
        """
        Interface to sudo command.
        """

        self.ssh: HostSSH = HostSSH(host)
        """
        Interface to ssh command.
        """

    def parametrize(self, method: str) -> HostSU | HostSSH:
        """
        Return authentication tool based on the method. The method can be
        either ``su`` or ``ssh``.

        :param method: ``su`` or ``ssh``
        :type method: str
        :raises ValueError: If invalid method is specified.
        :return: Authentication tool.
        :rtype: HostSU | HostSSH
        """

        allowed = ['su', 'ssh']
        if method not in allowed:
            raise ValueError(f'Unknown method {method}, choose from {allowed}.')

        return getattr(self, method)


class AuthBase(MultihostUtility):
    """
    Base class for authentication tools.
    """

    def _expect(self, script: str) -> int:
        """
        Execute expect script and return its return code.

        :param script: Expect script.
        :type script: str
        :return: Expect return code.
        :rtype: int
        """
        result = self.host.ssh.run('su --shell /bin/sh nobody -c "/bin/expect -d"', input=script, raise_on_error=False)
        return result.rc


class HostSU(AuthBase):
    """
    Interface to su command.
    """

    def password(self, username: str, password: str) -> bool:
        """
        Call ``su - $username`` and authenticate the user with password.

        :param name: User name.
        :type name: str
        :param password: User password.
        :type password: str
        :return: True if authentication was successful, False otherwise.
        :rtype: bool
        """

        rc = self._expect(rf"""
            # It takes some time to get authentication failure
            set timeout 10
            set prompt "\n.*\[#\$>\] $"

            spawn su - "{username}"

            expect {{
                "Password:" {{send "{password}\n"}}
                timeout {{puts "expect result: Unexpected su output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            expect {{
                -re $prompt {{puts "expect result: Password authentication successful"; exit 0}}
                "Authentication failure" {{puts "expect result: Authentication failure"; exit 4}}
                timeout {{puts "expect result: Unexpected su output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            puts "expect result: Unexpected code path"
            exit 3
        """)

        return rc == 0


class HostSSH(AuthBase):
    """
    Interface to ssh command.
    """

    def __init__(self, host: BaseHost) -> None:
        super().__init__(host)

        self.opts = '-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'

    def password(self, username: str, password: str) -> bool:
        """
        SSH to the remote host and authenticate the user with password.

        :param name: User name.
        :type name: str
        :param password: User password.
        :type password: str
        :return: True if authentication was successful, False otherwise.
        :rtype: bool
        """

        rc = self._expect(rf"""
            # It takes some time to get authentication failure
            set timeout 10
            set prompt "\n.*\[#\$>\] $"

            spawn ssh {self.opts} \
                -o PreferredAuthentications=password \
                -o NumberOfPasswordPrompts=1 \
                -l "{username}" localhost

            expect {{
                "password:" {{send "{password}\n"}}
                timeout {{puts "expect result: Unexpected su output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            expect {{
                -re $prompt {{puts "expect result: Password authentication successful"; exit 0}}
                "{username}@localhost: Permission denied" {{puts "expect result: Authentication failure"; exit 4}}
                timeout {{puts "expect result: Unexpected su output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            puts "expect result: Unexpected code path"
            exit 3
        """)

        return rc == 0


class HostSudo(AuthBase):
    """
    Interface to sudo command.
    """

    def run(self, username: str, password: str = None, *, command: str) -> bool:
        """
        Execute sudo command.

        :param username: Username that calls sudo.
        :type username: str
        :type command: str
        :param password: User password, defaults to None
        :param command: Command to execute (make sure to properly escape any quotes).
        :type password: str, optional
        :return: True if the command was successful, False if the command failed or the user can not run sudo.
        :rtype: bool
        """
        result = self.host.ssh.run(f'su - "{username}" -c "sudo --stdin {command}"', input=password, raise_on_error=False)

        return result.rc == 0

    def list(self, username: str, password: str = None, *, expected: list[str] = None) -> bool:
        """
        List commands that the user can run under sudo.

        :param username: Username that runs sudo.
        :type username: str
        :param password: User password, defaults to None
        :type password: str, optional
        :param expected: List of expected commands (formatted as sudo output), defaults to None
        :type expected: list[str], optional
        :return: True if the user can run sudo and allowed commands match expected commands (if set), False otherwise.
        :rtype: bool
        """
        result = self.host.ssh.run(f'su - "{username}" -c "sudo --stdin -l"', input=password, raise_on_error=False)
        if result.rc != 0:
            return False

        if expected is None:
            return True

        allowed = []
        for line in reversed(result.stdout_lines):
            if not line.startswith('    '):
                break
            allowed.append(line.strip())

        for line in expected:
            if line not in allowed:
                return False
            allowed.remove(line)

        if len(allowed) > 0:
            return False

        return True
