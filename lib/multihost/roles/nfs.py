from __future__ import annotations

from typing import TYPE_CHECKING

from ..host import NFSHost
from .base import BaseObject, LinuxRole

if TYPE_CHECKING:
    from ..multihost import Multihost


class NFS(LinuxRole):
    """
    NFS shared folders management.
    """

    def __init__(self, mh: Multihost, role: str, host: NFSHost) -> None:
        super().__init__(mh, role, host)
        self.hostname: str = host.hostname
        self.exports_dir: str = host.exports_dir

    def setup(self) -> None:
        """
        Setup NFS role.
        """
        super().setup()
        self.host.backup()

    def teardown(self) -> None:
        """
        Teardown NFS role.
        """
        self.host.restore()
        super().teardown()

    def exportfs_reload(self) -> None:
        """
        Reexport all directories.
        """
        self.host.exec('exportfs -r && exportfs -s')

    def export(
        self,
        path: str,
    ) -> NFSExport:
        return NFSExport(self, path)


class NFSExport(BaseObject):
    def __init__(self, role: NFS, path: str) -> None:
        super().__init__()
        self.role = role
        self.hostname = role.hostname
        self.path = path.strip('/')
        self.fullpath = f'{self.role.exports_dir}/{self.path}'
        self.exports_file = f'/etc/exports.d/{path.replace("/", "_")}.exports'
        self.opts: str = 'rw,sync,no_root_squash'

    def add(self, *, opts: str = 'rw,sync,no_root_squash', reload: bool = True) -> NFSExport:
        self.role.fs.mkdir_p(self.fullpath, mode='a=rwx')
        self.role.fs.write(self.exports_file, f'{self.fullpath} *({opts})')
        self.opts = opts

        if reload:
            self.role.exportfs_reload()

        return self

    def get(self) -> str:
        return f'-fstype=nfs,{self.opts} {self.hostname}:{self.fullpath}'
