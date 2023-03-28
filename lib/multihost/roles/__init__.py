from __future__ import annotations

from .ad import AD
from .base import BaseRole, LinuxRole, WindowsRole
from .client import Client
from .generic import GenericADProvider, GenericProvider
from .ipa import IPA
from .kdc import KDC
from .ldap import LDAP
from .nfs import NFS
from .samba import Samba
from .ipatuura import IPATuura

__all__ = [
    "AD",
    "BaseRole",
    "Client",
    "GenericADProvider",
    "GenericProvider",
    "IPA",
    "KDC",
    "LDAP",
    "LinuxRole",
    "NFS",
    "Samba",
    "WindowsRole",
    "IPATuura",
]


def get_role_class(role: str) -> type[BaseRole]:
    mapping = {
        'client': Client,
        'ad': AD,
        'ipa': IPA,
        'ldap': LDAP,
        'samba': Samba,
        'nfs': NFS,
        'kdc': KDC,
        'ipa': IPATuura,
    }

    if role not in mapping:
        raise ValueError(f'Unexpected role: {role}')

    return mapping[role]
