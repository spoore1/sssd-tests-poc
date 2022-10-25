from __future__ import annotations

import itertools
import shlex
import textwrap
from enum import Enum, auto
from typing import Any, Generator

import colorama as c
import pssh.clients
import pssh.clients.base.single
import pssh.clients.ssh
import pssh.output

from .logging import MultihostLogger


class SSHLog(Enum):
    """
    SSH command log level.
    """

    Silent = auto()
    """
    No log messages are produced.
    """

    Short = auto()
    """
    Command execution and return code is logged. Its output is omitted.
    """

    Full = auto()
    """
    Command execution, its return code and output is logged.
    """


class SSHClient(object):
    """
    Interactive SSH client.

    .. code-block:: python
        :caption: Example: Blocking call

        # Connect to SSH server, it is automatically disconnected when leaving the with statement
        with SSHClient(host, user=username, password=password, logger=logger) as ssh:
            result = ssh.run('echo Hello World')
            print(result.rc)
            print(result.stdout)

            result = ssh.run('cat', input='Hello World')
            print(result.rc)
            print(result.stdout)

    .. code-block:: python
        :caption: Example: Non-blocking call

        # Connect to SSH server, it is automatically disconnected when leaving the with statement
        with SSHClient(host, user=username, password=password, logger=logger) as ssh:
            # The process is executed, but it does not block. In order to wait for it to finish, run process.wait()
            process = ssh.async_run('echo Hello World')
            result = process.wait()
            print(result.rc)
            print(result.stdout)

            # You can write to stdin directly in asynchronous run
            process = ssh.async_run('cat')
            process.stdin.write('Hello World')
            process.send_eof()
            result = process.wait()
            print(result.rc)
            print(result.stdout)

            # You can also work with inputs and outputs more interactively.
            # The process is automatically waited when leaving the with statement.
            with ssh.async_run('bash') as process:
                process.stdin.write('echo Hello World\\n')
                print(next(process.stdout))

                process.stdin.write('echo This works as well\\n')
                print(next(process.stdout))
    """

    def __init__(
        self,
        host: str,
        *,
        user: str,
        password: str,
        port: int = 22,
        shell: str = '/usr/bin/bash -c',
        logger: MultihostLogger,
    ) -> None:
        """
        :param host: Host name to connect to.
        :type host: BaseRole | str
        :param user: Username to authenticate.
        :type user: str
        :param password: Password.
        :type password: str
        :param logger: Multihost logger.
        :type logger: MultihostLogger
        :param port: SSH port, defaults to 22
        :type port: int, optional
        :param shell: User shell used to run commands, defaults to '/usr/bin/bash -c'
        :type shell: str, optional
        """
        self.host: str = host
        self.user: str = user
        self.password: str = password
        self.port: int = port
        self.shell: str = shell
        self.logger: MultihostLogger = logger

        self.__conn: pssh.clients.ssh.SSHClient | None = None

    @property
    def connected(self) -> bool:
        """
        :return: True if the client is connected, False otherwise.
        :rtype: bool
        """
        return self.__conn is not None

    @property
    def conn(self) -> pssh.clients.ssh.SSHClient:
        """
        Low-level connection object.

        :return: Parallel-ssh connection object.
        :rtype: pssh.clients.ssh.SSHClient
        """
        if self.__conn is None:
            RuntimeError('SSH client is not connected.')

        return self.__conn

    def connect(self) -> None:
        """
        Connect to the host.
        """
        if self.connected:
            return

        self.logger.info(
            self.logger.colorize('Opening SSH connection to ', c.Style.BRIGHT)
            + self.logger.colorize(self.host, c.Fore.BLUE, c.Style.BRIGHT)
        )

        self.__conn = pssh.clients.ssh.SSHClient(
            host=self.host,
            user=self.user,
            password=self.password,
            port=self.port,
        )

    def disconnect(self) -> None:
        """
        Disconnect client.
        """
        self.logger.info(
            self.logger.colorize('Closing SSH connection to ', c.Style.BRIGHT)
            + self.logger.colorize(self.host, c.Fore.BLUE, c.Style.BRIGHT)
        )

        if not self.connected:
            return

        self.__conn.disconnect()
        self.__conn = None

    def async_run(
        self,
        command: str,
        *,
        cwd: str = None,
        env: dict[str, Any] = dict(),
        input: str | None = None,
        read_timeout: float = 30,
        log_level: SSHLog = SSHLog.Full,
    ) -> SSHProcess:
        """
        Non-blocking command call.

        The command is run under shell specified in the constructor and it is
        executed immediately, however it does not wait for the command to finish.

        :param command: Command to run.
        :type command: str
        :param cwd: Working directory, defaults to None (= do not change)
        :type cwd: str, optional
        :param env: Additional environment variables, defaults to dict()
        :type env: dict[str, Any], optional
        :param input: Content of standard input, defaults to None
        :type input: str | None, optional
        :param read_timeout: Timeout in seconds, how long should the client wait for output, defaults to 30 seconds
        :type read_timeout: float, optional
        :param log_level: Log level, defaults to SSHLog.Full
        :type log_level: SSHLog, optional
        :return: Instance of :class:`SSHProcess`, the process is already running.
        :rtype: SSHProcess
        """
        self.connect()

        process = SSHProcess(
            command=command,
            cwd=cwd,
            env=env,
            input=input,
            shell=self.shell,
            conn=self.conn,
            read_timeout=read_timeout,
            logger=self.logger,
            log_level=log_level,
            sync_exec=False,
        )

        process.run()
        return process

    def run(
        self,
        command: str,
        *,
        cwd: str = None,
        env: dict[str, Any] = dict(),
        input: str | None = None,
        read_timeout: float = 2,
        log_level: SSHLog = SSHLog.Full,
        raise_on_error: bool = True,
    ) -> SSHProcessResult:
        """
        Blocking command call.

        The command is run under shell specified in the constructor and it is
        executed immediately. It waits for the command to finish and returns
        its result.

        :param command: Command to run.
        :type command: str
        :param cwd: Working directory, defaults to None (= do not change)
        :type cwd: str, optional
        :param env: Additional environment variables, defaults to dict()
        :type env: dict[str, Any], optional
        :param input: Content of standard input, defaults to None
        :type input: str | None, optional
        :param read_timeout: Timeout in seconds, how long should the client wait
            for output, defaults to 30 seconds
        :type read_timeout: float, optional
        :param log_level: Log level, defaults to SSHLog.Full
        :type log_level: SSHLog, optional
        :param raise_on_failure: If True, raise :class:`SSHProcessError` if command exited with non-zero return code.
        :type log_level: SSHLog, optional
        :return: Command result.
        :rtype: SSHProcessResult
        """
        self.connect()

        process = SSHProcess(
            command=command,
            cwd=cwd,
            env=env,
            input=input,
            shell=self.shell,
            conn=self.conn,
            read_timeout=read_timeout,
            logger=self.logger,
            log_level=log_level,
            sync_exec=True,
        )

        process.run()

        return process.wait(raise_on_error=raise_on_error)

    def async_exec(
        self,
        argv: list[Any],
        *,
        cwd: str = None,
        env: dict[str, Any] = dict(),
        input: str | None = None,
        read_timeout: float = 2,
        log_level: SSHLog = SSHLog.Full,
    ) -> SSHProcess:
        """
        Non-blocking command call.

        The command is run under shell specified in the constructor and it is
        executed immediately, however it does not wait for the command to finish.

        The command is provided as ``argv`` list.

        :param argv: Command to run.
        :type argv: str
        :param cwd: Working directory, defaults to None (= do not change)
        :type cwd: str, optional
        :param env: Additional environment variables, defaults to dict()
        :type env: dict[str, Any], optional
        :param input: Content of standard input, defaults to None
        :type input: str | None, optional
        :param read_timeout: Timeout in seconds, how long should the client wait for output, defaults to 30 seconds
        :type read_timeout: float, optional
        :param log_level: Log level, defaults to SSHLog.Full
        :type log_level: SSHLog, optional
        :return: Instance of :class:`SSHProcess`, the process is already running.
        :rtype: SSHProcess
        """
        argv = [str(x) for x in argv]
        command = shlex.join(argv)

        return self.async_run(
            command,
            cwd=cwd,
            env=env,
            input=input,
            read_timeout=read_timeout,
            log_level=log_level,
        )

    def exec(
        self,
        argv: list[Any],
        *,
        cwd: str = None,
        env: dict[str, Any] = dict(),
        input: str | None = None,
        read_timeout: float = 2,
        log_level: SSHLog = SSHLog.Full,
        raise_on_error: bool = True,
    ) -> SSHProcessResult:
        """
        Blocking command call.

        The command is run under shell specified in the constructor and it is
        executed immediately. It waits for the command to finish and returns
        its result.

        The command is provided as ``argv`` list.

        :param argv: Command to run.
        :type argv: str
        :param cwd: Working directory, defaults to None (= do not change)
        :type cwd: str, optional
        :param env: Additional environment variables, defaults to dict()
        :type env: dict[str, Any], optional
        :param input: Content of standard input, defaults to None
        :type input: str | None, optional
        :param read_timeout: Timeout in seconds, how long should the client wait
            for output, defaults to 30 seconds
        :type read_timeout: float, optional
        :param log_level: Log level, defaults to SSHLog.Full
        :type log_level: SSHLog, optional
        :param raise_on_failure: If True, raise :class:`SSHProcessError` if command exited with non-zero return code.
        :type log_level: SSHLog, optional
        :return: Command result.
        :rtype: SSHProcessResult
        """
        process = self.async_exec(
            argv,
            cwd=cwd,
            env=env,
            input=input,
            read_timeout=read_timeout,
            log_level=log_level,
        )

        return process.wait(raise_on_error=raise_on_error)

    def expect(self, expect_script: str) -> SSHProcessResult:
        """
        Run expect script.

        :param expect_script: Expect script.
        :type expect_script: str
        :return: Expect script result.
        :rtype: SSHProcessResult
        """
        return self.run('/bin/expect -d', input=expect_script, raise_on_error=False)

    def __enter__(self) -> SSHClient:
        """
        Connect to the host.

        :return: SSHClient instance.
        :rtype: SSHClient
        """
        self.connect()
        return self

    def __exit__(self, exception_type, exception_value, traceback) -> None:
        """
        Disconnect.
        """
        self.disconnect()


class SSHProcess(object):
    """
    SSH Process.

    .. note::

        You should not create instances of this class yourself. Use method
        :meth:`SSHClient.run`, :meth:`SSHClient.exec`,
        :meth:`SSHClient.async_run` and :meth:`SSHClient.async_exec` from
        :class:`SSHClient` to execute a command over SSH.
    """

    __genid = itertools.count()

    def __init__(
        self,
        *,
        command: str,
        cwd: str = None,
        env: dict[str, Any] = dict(),
        input: str | None = None,
        shell: str = '/usr/bin/bash -c',
        conn: pssh.clients.ssh.SSHClient,
        read_timeout: float,
        logger: MultihostLogger,
        log_level: SSHLog,
        sync_exec: bool,
    ) -> None:
        """
        :param command: Command to execute.
        :type command: str
        :param conn: Connected SSH client.
        :type conn: pssh.clients.ssh.SSHClient
        :param read_timeout: Timeout in seconds, how long should the client wait
            for output, defaults to 30 seconds
        :type read_timeout: float
        :param logger: Multihost logger.
        :type logger: MultihostLogger
        :param log_level: Log level.
        :type log_level: SSHLog
        :param sync_exec: Is this a blocking execution?
        :type sync_exec: bool
        :param cwd: Working directory, defaults to None
        :type cwd: str, optional
        :param env: Additional environment variables, defaults to dict()
        :type env: dict[str, Any], optional
        :param input: Content of standard input, defaults to None
        :type input: str | None, optional
        :param shell: Shell used to execute the command, defaults to '/usr/bin/bash -c'
        :type shell: str, optional
        """
        self.__conn: pssh.clients.ssh.SSHClient = conn
        self.__process: pssh.output.HostOutput | None = None

        self.__logger: MultihostLogger = logger
        self.__log_level: SSHLog = log_level
        self.__sync_exec: bool = sync_exec

        self.id = next(self.__genid) + 1
        self.command: str = textwrap.dedent(command).strip()
        self.cwd: str | None = cwd
        self.env: dict[str, Any] = env
        self.input: str | None = input
        self.shell: str = shell
        self.read_timeout: float = read_timeout

        self.__stdout_generator: Generator[str, None, None] | None = None
        self.__stderr_generator: Generator[str, None, None] | None = None
        self.__stdout: list[str] = []
        self.__stderr: list[str] = []

    @property
    def stdout(self) -> Generator[str, None, None]:
        """
        Standard output, returns generator which yields output line by line.

        .. code-block:: python

            # Read single line, this will block until there is a line to read or read_timeout is reached
            line = next(process.stdout)

            # Read all lines, this will block until EOF or read_timeout is reached
            lines = list(process.stdout)

            # Iterate over all lines
            for line in process.stdout:
                pass

        :raises RuntimeError: If the process is not yet started.
        :return: Standard output generator.
        :rtype: Generator[str, None, None]
        """
        if self.__stdout_generator is None:
            raise RuntimeError('The process has not yet started')

        return self.__stdout_generator

    @property
    def stderr(self) -> Generator[str, None, None]:
        """
        Standard error output, returns generator which yields error output line by line.

        .. code-block:: python

            # Read single line, this will block until there is a line to read or read_timeout is reached
            line = next(process.stderr)

            # Read all lines, this will block until EOF or read_timeout is reached
            lines = list(process.stderr)

            # Iterate over all lines
            for line in process.stderr:
                pass

        :raises RuntimeError: If the process is not yet started.
        :return: Standard error output generator.
        :rtype: Generator[str, None, None]
        """
        if self.__stderr_generator is None:
            raise RuntimeError('The process has not yet started')

        return self.__stderr_generator

    @property
    def stdin(self) -> pssh.clients.base.single.Stdin:
        """
        File-like object representing command's standard input.

        .. code-block:: python

            # Write data
            process.stdin.write('Hello World')

            # Send EOF to indicate that there will be no more input data.
            process.send_eof()

        :raises RuntimeError: If the process is not yet started.
        :return: Standard input file.
        :rtype: pssh.clients.base.single.Stdin
        """

        if self.__process is None:
            raise RuntimeError('The process has not yet started')

        return self.__process.stdin

    def run(self) -> SSHProcess:
        """
        Execute the command.

        :return: Self.
        :rtype: SSHProcess
        """
        complete_command = self.__build_complete_command(
            self.command,
            cwd=self.cwd,
            env=self.env
        )

        if self.__log_level != SSHLog.Silent:
            self.__logger.info(
                self.__msg_execution(),
                extra={'data': {
                    'Host': self.__conn.host,
                    'User': self.__conn.user,
                    'Command': self.command,
                    'Input': self.input,
                    'Working directory': self.cwd,
                    'Extra environment': self.env,
                }}
            )

        self.__process = self.__conn.run_command(
            command=complete_command,
            shell=self.shell,
            read_timeout=self.read_timeout,
        )

        def wrap_generator(generator, buffer) -> Generator[str, None, None]:
            for line in generator:
                buffer.append(line)
                yield line

        self.__stdout_generator = wrap_generator(self.__process.stdout, self.__stdout)
        self.__stderr_generator = wrap_generator(self.__process.stderr, self.__stderr)

        if self.input is not None:
            self.stdin.write(self.input)

        return self

    def wait(self, raise_on_error: bool = True) -> SSHProcessResult:
        """
        Wait for the command to finish.

        EOF is send to standard input to indicate that there will be no
        additional input data. Then it waits for the command to finish.

        :param raise_on_error: If True, :class:`SSHProcessError` is raised on non-zero return code, defaults to True
        :type raise_on_error: bool, optional
        :raises SSHProcessError: If ``raise_on_error`` is True and the command exited with non-zero return code.
        :return: Command result.
        :rtype: SSHProcessResult
        """
        self.send_eof()
        self.__conn.wait_finished(self.__process)

        # Read remaining output, this will finish the output generator and append
        # remaining lines to self.__stdout and self.__stderr buffers.
        list(self.stdout)
        list(self.stderr)

        result = SSHProcessResult(self.__process.exit_code, self.__stdout, self.__stderr)

        if self.__sync_exec:
            match self.__log_level:
                case SSHLog.Short:
                    self.__logger.info(self.__msg_completed_sync(result.rc))
                case SSHLog.Full:
                    self.__logger.info(
                        self.__msg_completed_sync(result.rc),
                        extra={'data': {
                            'Output': result.stdout,
                            'Error output': result.stderr,
                        }}
                    )
                case _:
                    pass
        else:
            match self.__log_level:
                case SSHLog.Short:
                    self.__logger.info(
                        self.__msg_completed_async(result.rc),
                        extra={'data': {
                            'Host': self.__conn.host,
                            'User': self.__conn.user,
                            'Command': self.command,
                            'Input': self.input,
                            'Working directory': self.cwd,
                            'Extra environment': self.env,
                        }}
                    )
                case SSHLog.Full:
                    self.__logger.info(
                        self.__msg_completed_async(result.rc),
                        extra={'data': {
                            'Host': self.__conn.host,
                            'User': self.__conn.user,
                            'Command': self.command,
                            'Input': self.input,
                            'Working directory': self.cwd,
                            'Extra environment': self.env,
                            'Output': result.stdout,
                            'Error output': result.stderr,
                        }}
                    )
                case _:
                    pass

        if raise_on_error and result.rc != 0:
            raise SSHProcessError(
                self.id,
                self.command,
                result.rc,
                self.cwd,
                self.env,
                self.input,
                result.stdout,
                result.stderr
            )

        return result

    def send_eof(self) -> None:
        """
        Send EOF to standard input to indicate that there will be no more
        input data.

        :raises RuntimeError: If the process is not yet started.
        """
        if self.__process is None:
            raise RuntimeError('The process has not yet started')

        self.__process.channel.send_eof()

    def __build_complete_command(self, command: str, *, cwd: str | None, env: dict[str, Any]) -> str:
        out = ''

        # Set environment variables
        for key, value in env.items():
            out += f'export {key}={shlex.quote(str(value))}\n'

        # Set working directory
        if cwd is not None:
            out += f"cd '{shlex.quote(cwd)}'\n"

        if out:
            out += '\n'

        out += command

        return out

    def __msg_id(self) -> str:
        return self.__logger.colorize(f"#{self.id}", c.Style.BRIGHT, c.Fore.BLUE)

    def __msg_rc(self, rc: int) -> str:
        if rc == 0:
            return self.__logger.colorize(rc, c.Style.BRIGHT, c.Fore.GREEN)

        return self.__logger.colorize(rc, c.Style.BRIGHT, c.Fore.RED)

    def __msg_execution(self) -> str:
        return f'{self.__logger.colorize("Executing command", c.Style.BRIGHT)} ' \
            + self.__msg_id()

    def __msg_completed_sync(self, rc: int) -> str:
        return self.__logger.colorize('Previous command completed with exit code ', c.Style.BRIGHT) \
            + self.__msg_rc(rc)

    def __msg_completed_async(self, rc: int) -> str:
        return self.__logger.colorize('Command ', c.Style.BRIGHT) \
            + self.__msg_id() \
            + self.__logger.colorize(' completed with exit code ', c.Style.BRIGHT) \
            + self.__msg_rc(rc)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.wait()


class SSHProcessResult(object):
    """
    SSH Process result.
    """
    def __init__(self, rc: int, stdout: list[str], stderr: list[str]) -> None:
        """
        :param rc: Return code.
        :type rc: int
        :param stdout: Standard output, line by line.
        :type stdout: list[str]
        :param stderr: Standard error output, line by line.
        :type stderr: list[str]
        """
        self.rc = rc
        self.stdout: str = '\n'.join(stdout)
        self.stderr: str = '\n'.join(stderr)
        self.stdout_lines: list[str] = stdout
        self.stderr_lines: list[str] = stderr


class SSHProcessError(Exception):
    """
    SSH Process Error.
    """
    def __init__(
        self,
        id: int,
        command: str,
        rc: int,
        cwd: str | None,
        env: dict[str, Any],
        input: str | None,
        stdout: str,
        stderr: str
    ) -> None:
        pretty_env = ''
        for key, value in env.items():
            pretty_env += f'{key}={value}\n'

        def dumps(value) -> str:
            if not value:
                return ''

            return '\n' + textwrap.indent(value, ' ' * 12)

        super().__init__(textwrap.dedent(f'''
        Command #{id} exited with return code {rc}:
          Command:{dumps(command)}
          CWD:{dumps(cwd)}
          Env:{dumps(pretty_env.strip())}
          Output:{dumps(stdout)}
          Error output:{dumps(stderr)}
        '''))

        self.id = id
        self.command = command,
        self.rc = rc
        self.cwd = cwd
        self.env = env
        self.input = input
        self.stdout = stdout
        self.stderr = stderr