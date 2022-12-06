from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from .config import MultihostConfig, MultihostDomain
from .host import MultihostHost
from .logging import MultihostLogger
from .roles import BaseRole, get_role_class
from .topology import Topology, TopologyDomain

if TYPE_CHECKING:
    from .plugin.plugin import MultihostItemData


class Multihost(object):
    """
    Multihost object provides access to underlaying multihost configuration,
    individual domains and hosts. This object should be used only in tests
    as the :func:`lib.multihost.plugin.mh` pytest fixture.

    Domains are accessible as dynamically created properties of this object,
    hosts are accessible by roles as dynamically created properties of each
    domain. Each host object is instance of specific role class from
    :mod:`lib.multihost.roles`.

    .. code-block:: yaml
        :caption: Example multihost configuration

        domains:
        - name: ldap.test
          type: sssd
          hosts:
          - name: client
            external_hostname: client.ldap.test
            role: client

          - name: ldap
            external_hostname: master.ldap.test
            role: ldap

    The configuration above creates one domain of type ``sssd`` with two hosts.
    The following example shows how to access the hosts:

    .. code-block:: python
        :caption: Example of the Multihost object

        def test_example(mh: Multihost):
            mh.sssd            # -> namespace containing roles as properties
            mh.sssd.client     # -> list of hosts providing given role
            mh.sssd.client[0]  # -> host object, instance of specific role
    """

    def __init__(self, request: pytest.FixtureRequest, multihost: MultihostConfig, topology: Topology) -> None:
        """
        :param multihost: Multihost configuration.
        :type multihost: MultihostConfig
        """

        self.data: MultihostItemData = request.node.multihost
        """
        Multihost item data.
        """

        self.request: pytest.FixtureRequest = request
        """
        Pytest request.
        """

        self.multihost: MultihostConfig = multihost
        """
        Multihost configuration.
        """

        self.logger: MultihostLogger = multihost.logger
        """
        Multihost logger.
        """

        self._paths = {}

        for domain in self.multihost.domains:
            if domain.type in topology:
                setattr(self, domain.type, self._domain_to_namespace(domain, topology.get(domain.type)))

    def _domain_to_namespace(self, domain: MultihostDomain, topology_domain: TopologyDomain) -> SimpleNamespace:
        ns = SimpleNamespace()
        for role_name in domain.roles:
            if role_name not in topology_domain:
                continue

            count = topology_domain.get(role_name)
            roles = [self._host_to_role(host) for host in domain.hosts_by_role(role_name)[:count]]

            self._paths[f'{domain.type}.{role_name}'] = roles
            for index, role in enumerate(roles):
                self._paths[f'{domain.type}.{role_name}[{index}]'] = role

            setattr(ns, role_name, roles)

        return ns

    def _host_to_role(self, host: MultihostHost):
        cls = get_role_class(host.role)
        return cls(self, host.role, host)

    def _lookup(self, path: str) -> BaseRole | list[BaseRole]:
        """
        Lookup host by path. The path format is ``$domain.$role``
        or ``$domain.$role[$index]``

        :param path: Host path.
        :type path: str
        :raises LookupError: If host is not found.
        :return: The role object if index was given, list of role objects otherwise.
        :rtype: BaseRole | list[BaseRole]
        """

        if path not in self._paths:
            raise LookupError(f'Name "{path}" does not exist')

        return self._paths[path]

    @property
    def _hosts_and_roles(self) -> list[MultihostHost | BaseRole]:
        """
        :return: List containing all hosts and roles available for current test case.
        :rtype: list[MultihostHost | BaseRole]
        """
        roles: list[BaseRole] = [x for x in self._paths.values() if isinstance(x, BaseRole)]
        hosts: list[MultihostHost] = [x.host for x in roles]

        return list(set(hosts + roles))

    def _setup(self) -> None:
        """
        Setup multihost. A setup method is called on each host and role
        to initialize the test environment to expected state.
        """
        setup_ok: list[MultihostHost | BaseRole] = []
        for item in self._hosts_and_roles:
            try:
                item.setup()
            except Exception:
                # Teardown hosts and roles that were successfully setup before this error
                for i in reversed(setup_ok):
                    i.teardown()
                raise

            setup_ok.append(item)

    def _teardown(self) -> None:
        """
        Teardown multihost. The purpose of this method is to revert any changes
        that were made during a test run. It is automatically called when the
        test is finished.
        """
        errors = []
        for item in reversed(self._hosts_and_roles):
            try:
                if isinstance(item, BaseRole):
                    item.collect_artifacts()
                item.teardown()
            except Exception as e:
                errors.append(e)

        if errors:
            raise Exception(errors)

    def __enter__(self) -> 'Multihost':
        self._setup()
        return self

    def __exit__(self, exception_type, exception_value, traceback) -> None:
        self._teardown()
