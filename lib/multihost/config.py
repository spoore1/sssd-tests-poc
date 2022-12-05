from __future__ import annotations

from typing import Any, Type

from .host import ADHost, IPAHost, KDCHost, LDAPHost, MultihostHost, NFSHost, SambaHost
from .logging import MultihostLogger


class MultihostDomain(object):
    """
    Multihost domain class.
    """

    def __init__(self, config: MultihostConfig, confdict: dict[str, Any]) -> None:
        if 'type' not in confdict:
            raise ValueError('"type" property is missing in domain configuration')

        if 'hosts' not in confdict:
            raise ValueError('"hosts" property is missing in domain configuration')

        self.config: MultihostConfig = config
        """Multihost configuration"""

        self.logger: MultihostLogger = config.logger
        """Multihost logger"""

        self.type: str = confdict['type']
        """Domain type"""

        self.hosts: list[MultihostHost] = []
        """Available hosts in this domain"""

        for host in confdict['hosts']:
            self.hosts.append(self._create_host(host))

    @property
    def roles(self) -> list[str]:
        """
        All roles available in this domain.

        :return: Role names.
        :rtype: list[str]
        """
        return sorted(set(x.role for x in self.hosts))

    def _create_host(self, confdict: dict[str, Any]) -> MultihostHost:
        """
        Find desired host class by role.

        :param confdict: Host configuration as a dictionary.
        :type confdict: dict[str, any]
        :return: Host instance.
        :rtype: MultihostHost
        """
        if not confdict.get('role', None):
            raise ValueError('"role" property is missing in host configuration')

        role = confdict['role']
        cls = self.host_classes[role] if role in self.host_classes else MultihostHost

        return cls(self, confdict)

    @property
    def host_classes(self) -> Type[MultihostHost]:
        """
        Map role to host class.

        :rtype: Class name.
        """

        return {
            'ad': ADHost,
            'ldap': LDAPHost,
            'ipa': IPAHost,
            'samba': SambaHost,
            'nfs': NFSHost,
            'kdc': KDCHost,
        }

    def hosts_by_role(self, role: str) -> list[MultihostHost]:
        """
        Return all hosts of the given role.

        :param role: Role name.
        :type role: str
        :return: List of hosts of given role.
        :rtype: list[MultihostHost]
        """
        return [x for x in self.hosts if x.role == role]


class MultihostConfig(object):
    """
    Multihost configuration.
    """

    def __init__(
        self,
        confdict: dict[str, Any],
        *,
        log_path: str | None = None,
        lazy_ssh: bool = False
    ) -> None:
        self.logger: MultihostLogger = MultihostLogger.Setup(log_path)
        """Multihost logger"""

        self.lazy_ssh: bool = lazy_ssh
        """If True, hosts postpone connecting to ssh when the connection is first required"""

        self.domains: list[MultihostDomain] = []
        """Available domains"""

        if 'domains' not in confdict:
            raise ValueError('"domains" property is missing in multihost configuration')

        for domain in confdict['domains']:
            self.domains.append(MultihostDomain(self, domain))

    def get_domain_class(self) -> Type[MultihostDomain]:
        return MultihostDomain
