from __future__ import annotations

from ..command import RemoteCommandResult
from ..host import BaseHost
from .base import MultihostUtility


class HostService(MultihostUtility):
    """
    Manage remote services.
    """

    def __init__(self, host: BaseHost) -> None:
        super().__init__(host)
        self.initial_states: dict[str, bool] = {}

    def teardown(self) -> None:
        # Restart all services that were touched
        for service, state in self.initial_states.items():
            self.__systemctl('stop', service, raise_on_error=False, wait=True)
            if state:
                self.__systemctl('start', service, raise_on_error=False, wait=True)

    def start(self, service: str, raise_on_error: bool = True, wait: bool = True) -> RemoteCommandResult:
        """
        Start a systemd unit.

        ``systemctl status $unit`` is called automatically if the unit can not
        be started. The status is then visible in the logs.

        :param service: Unit name.
        :type service: str
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :param wait: Wait for the command to finish, defaults to True
        :type wait: bool, optional
        :return: Remote command result.
        :rtype: RemoteCommandResult
        """
        self.__set_initial_state(service)
        return self.__systemctl('start', service, raise_on_error, wait)

    def stop(self, service: str, raise_on_error: bool = True, wait: bool = True) -> RemoteCommandResult:
        """
        Stop a systemd unit.

        ``systemctl status $unit`` is called automatically if the unit can not
        be stopped. The status is then visible in the logs.

        :param service: Unit name.
        :type service: str
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :param wait: Wait for the command to finish, defaults to True
        :type wait: bool, optional
        :return: Remote command result.
        :rtype: RemoteCommandResult
        """
        self.__set_initial_state(service)
        return self.__systemctl('stop', service, raise_on_error, wait)

    def restart(self, service: str, raise_on_error: bool = True, wait: bool = True) -> RemoteCommandResult:
        """
        Restart a systemd unit.

        ``systemctl status $unit`` is called automatically if the unit can not
        be restarted. The status is then visible in the logs.

        :param service: Unit name.
        :type service: str
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :param wait: Wait for the command to finish, defaults to True
        :type wait: bool, optional
        :return: Remote command result.
        :rtype: RemoteCommandResult
        """
        self.__set_initial_state(service)
        return self.__systemctl('restart', service, raise_on_error, wait)

    def reload(self, service: str, raise_on_error: bool = True, wait: bool = True) -> RemoteCommandResult:
        """
        Reload a systemd unit.

        ``systemctl status $unit`` is called automatically if the unit can not
        be reloaded. The status is then visible in the logs.

        :param service: Unit name.
        :type service: str
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :param wait: Wait for the command to finish, defaults to True
        :type wait: bool, optional
        :return: Remote command result.
        :rtype: RemoteCommandResult
        """
        return self.__systemctl('reload', service, raise_on_error, wait)

    def status(self, service: str, raise_on_error: bool = False, wait: bool = True) -> RemoteCommandResult:
        """
        Get systemd unit status.

        :param service: Unit name.
        :type service: str
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :param wait: Wait for the command to finish, defaults to True
        :type wait: bool, optional
        :return: Remote command result.
        :rtype: RemoteCommandResult
        """
        return self.host.exec(['systemctl', 'status', service], raise_on_error=raise_on_error, wait=wait)

    def reload_daemon(self, raise_on_error: bool = False, wait: bool = True) -> RemoteCommandResult:
        """
        Reload systemd daemon to refresh unit files.

        :param service: Unit name.
        :type service: str
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :param wait: Wait for the command to finish, defaults to True
        :type wait: bool, optional
        :return: Remote command result.
        :rtype: RemoteCommandResult
        """
        return self.host.exec(['systemctl', 'daemon-reload'], raise_on_error=raise_on_error, wait=wait)

    def __systemctl(self, command: str, service: str, raise_on_error: bool, wait: bool) -> RemoteCommandResult:
        try:
            result = self.host.exec(['systemctl', command, service], raise_on_error=raise_on_error, wait=wait)
            if result.rc != 0:
                self.status(service)
        except Exception:
            # Get service status to see why it failed
            self.status(service)
            raise

        return result

    def __set_initial_state(self, service: str) -> None:
        if service in self.initial_states:
            return

        result = self.status(service, raise_on_error=False)
        self.initial_states[service] = result.rc == 0
