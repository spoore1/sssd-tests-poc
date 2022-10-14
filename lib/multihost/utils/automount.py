from __future__ import annotations

from ..host import BaseHost
from ..roles.nfs import NFSExport
from .base import MultihostUtility
from .service import HostService


class HostAutomount(MultihostUtility):
    """
    API for automount testing.

    All changes are automatically reverted when a test is finished.
    """

    def __init__(self, host: BaseHost, svc: HostService) -> None:
        """
        :param host: Remote host instance.
        :type host: BaseHost
        """
        super().__init__(host)
        self.svc = svc
        self.__started: bool = False

    def reload(self) -> None:
        """
        Reload autofs maps.
        """
        self.svc.start('autofs')
        self.svc.reload('autofs')

    def mount(self, path: str, export: NFSExport) -> bool:
        """
        Try to mount the autofs directory by accessing it. Returns ``True``
        if the mount was successful, ``False`` otherwise.

        :param path: Path to the autofs mount point.
        :type path: str
        :param export: Expected NFS location that should be mounted on the mount point.
        :type export: NFSExport
        :return: ``True`` if the mount was successful, ``False`` otherwise.
        :rtype: bool
        """

        result = self.host.exec(rf'''
        set -ex
        pushd "{path}"
        mount | grep "{export.hostname}:{export.fullpath} on {path}"
        popd
        umount "{path}"
        ''', raise_on_error=False)

        return result.rc == 0

    def dumpmaps(self) -> dict[str, dict[str, list[str]]]:
        """
        Calls ``automount -m``, parses its output into a dictionary and returns the dictionary.

        .. code-block:: python
            :caption: Dictionary format

            {
                '$mountpoint': {
                    'map': '$mapnam',
                    'keys': ['$key1', '$key2']
                }
            }

        .. code-block:: python
            :caption: Example

            {
                '/ehome': {
                    'map': 'auto.home',
                    'keys': [
                        'export1 | -fstype=nfs,rw,sync,no_root_squash nfs.test:/dev/shm/exports/export1',
                        'export2 | -fstype=nfs,rw,sync,no_root_squash nfs.test:/dev/shm/exports/export2'
                    ]
                },
                '/esub/sub1/sub2': {
                    'map': 'auto.sub',
                    'keys': ['export3 | -fstype=nfs,rw,sync,no_root_squash nfs.test:/dev/shm/exports/sub/export3']
                },
            }

        .. note::

            Only mountpoints defined by SSSD are present in the output.

        :return: Parsed ``automount -m`` output.
        :rtype: dict[str, dict[str, list[str]]]
        """
        result = self.host.exec('automount -m')

        def parse_result(lines: list[str]) -> dict[str, dict[str, list[str]]]:
            mountpoints = {}
            for i, l in enumerate(lines):
                if l.startswith('Mount point: '):
                    point = l.replace('Mount point: ', '').strip()
                    for k, l2 in enumerate(lines[i + 1:], i + 1):
                        if l2.startswith('Mount point: '):
                            break

                    data = lines[i + 1:k]
                    if 'instance type(s): sss' not in data:
                        continue

                    data.remove('source(s):')
                    data.remove('instance type(s): sss')

                    mapname = None
                    for k, l in enumerate(data):
                        if l.startswith('map: '):
                            mapname = l.replace('map: ', '').strip()
                            del data[k]

                    data = [x.strip() for x in data if x]
                    mountpoints[point] = {'map': mapname, 'keys': data}

            return mountpoints

        return parse_result([x.strip() for x in result.stdout_lines])
