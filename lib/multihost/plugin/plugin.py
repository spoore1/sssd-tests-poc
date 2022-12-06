from __future__ import annotations

import inspect
import logging
import sys
import textwrap

import pytest
import yaml

from ..config import MultihostConfig
from ..topology import Topology
from .marks import TopologyMark


class MultihostItemData(object):
    """
    Multihost internal pytest data, stored in :attr:`pytest.Item.multihost`
    """

    def __init__(
        self,
        multihost: MultihostConfig | None,
        topology_mark: TopologyMark | None
    ) -> None:
        self.multihost: MultihostConfig = multihost
        """
        Multihost object.
        """

        self.topology_mark: TopologyMark = topology_mark
        """
        Topology mark for the test run.
        """

        self.outcome: str = None
        """
        Test run outcome, available in fixture finalizers.
        """


class MultihostPlugin(object):
    """
    Pytest multihost plugin. See lib.multihost.plugin docstring for description.
    """

    def __init__(self, config: pytest.Config) -> None:
        self.logger: logging.Logger = self._create_logger(config.option.verbose > 2)
        self.multihost: MultihostConfig | None = None
        self.topology: Topology | None = None
        self.exact_topology: bool = config.getoption('exact_topology')
        self.artifacts_dir: bool = config.getoption('artifacts_dir')
        self.collect_artifacts: bool = config.getoption('collect_artifacts')
        self.multihost_log_path: str = config.getoption('mh_log_path')
        self.multihost_config_path: str = config.getoption('mh_config')
        self.multihost_lazy_ssh: str = config.getoption('mh_lazy_ssh')
        self.confdict: dict | None = None

    @classmethod
    def GetLogger(cls) -> logging.Logger:
        """
        Get plugin's logger.
        """

        return logging.getLogger('lib.multihost.plugin')

    def __load_conf(self, path: str) -> dict:
        """
        Load multihost configuration from a yaml file.

        :param path: Path to the yaml file.
        :type path: str
        :raises ValueError: If not file was provided.
        :raises IOError: If unable to read the file.
        :return: Parsed configuration.
        :rtype: dict

        :meta private:
        """
        if not path:
            raise ValueError('You need to provide valid multihost configuration file, use --mh-config=$path')

        try:
            with open(path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            raise IOError(f'Unable to open multihost configuration "{path}": {str(e)}')

    def setup(self) -> None:
        """
        Read and apply multihost configuration.

        :meta private:
        """
        self.confdict = self.__load_conf(self.multihost_config_path)

        self.multihost = MultihostConfig(
            self.confdict,
            log_path=self.multihost_log_path,
            lazy_ssh=self.multihost_lazy_ssh
        )

        self.topology = Topology.FromMultihostConfig(self.confdict)

    @pytest.hookimpl(trylast=True)
    def pytest_sessionstart(self, session: pytest.Session) -> None:
        """
        Setup the module and log information about given multihost configuration
        and provided options.

        :meta private:
        """
        # Calling the setup here instead of in constructor to allow running
        # pytest --help and other action-less parameters.
        self.setup()

        if self.multihost is None:
            self.logger.info(self._fmt_bold('Multihost configuration:'))
            self.logger.info('  No multihost configuration provided.')
            self.logger.info('  Make sure to run tests with --mh-log-path parameter.')
            self.logger.info('')
            return

        self.logger.info(self._fmt_bold('Multihost configuration:'))
        self.logger.info(textwrap.indent(yaml.dump(self.confdict, sort_keys=False), '  '))
        self.logger.info(self._fmt_bold('Detected topology:'))
        self.logger.info(textwrap.indent(yaml.dump(self.topology.export(), sort_keys=False), '  '))
        self.logger.info(self._fmt_bold('Additional settings:'))
        self.logger.info(f'  multihost log path: {self.multihost_log_path}')
        self.logger.info(f'  lazy ssh: {self.multihost_lazy_ssh}')
        self.logger.info(f'  require exact topology: {self.exact_topology}')
        self.logger.info(f'  collect artifacts: {self.collect_artifacts}')
        self.logger.info(f'  artifacts directory: {self.artifacts_dir}')
        self.logger.info('')

    @pytest.hookimpl(hookwrapper=True)
    def pytest_make_collect_report(self, collector: pytest.Collector) -> pytest.CollectReport:
        """
        If multiple topology marks are present on the collected test, we need to
        parametrize it. In order to do so, the test is replaced with multiple
        clones, one for each topology.

        The topology associated with the test clone is stored in
        ``topology_mark`` property of the clone.

        :meta private:
        """

        outcome = yield
        report = outcome.get_result()

        if not report.result:
            return

        new_result = []
        for result in report.result:
            if not isinstance(result, pytest.Function):
                new_result.append(result)
                continue

            has_marks = False
            for mark in TopologyMark.ExpandMarkers(result):
                has_marks = True
                topology_mark = TopologyMark.Create(result, mark)
                f = self._clone_function(f'{result.name} ({topology_mark.name})', result)
                f.topology_mark = topology_mark
                new_result.append(f)

            if not has_marks:
                result.topology_mark = None
                new_result.append(result)

        report.result = new_result

    @pytest.hookimpl(tryfirst=True)
    def pytest_collection_modifyitems(self, config: pytest.Config, items: list[pytest.Item]) -> None:
        """
        Filter collected items and deselect these that can not be run on the
        selected multihost configuration.

        Internal plugin's data are stored in ``multihost`` property of each
        :class:`pytest.Item`.

        :meta private:
        """

        selected = []
        deselected = []

        for item in items:
            data = MultihostItemData(self.multihost, item.topology_mark) if self.multihost else None
            item.multihost = data

            if not self._can_run_test(item, item.multihost):
                deselected.append(item)
                continue

            selected.append(item)

        config.hook.pytest_deselected(items=deselected)
        items[:] = selected

    @pytest.hookimpl(tryfirst=True)
    def pytest_runtest_setup(self, item: pytest.Item) -> None:
        """
        Create fixtures requested in :class:`lib.multihost.plugin.TopologyMark`
        (``@pytest.mark.topology``). It adds the fixture names into ``funcargs``
        property of the pytest item in order to make them available.

        At this step, the fixtures do not have any value. The value is assigned
        later in :func:`pytest_runtest_call` hook.

        :meta private:
        """

        data:  MultihostItemData = item.multihost
        if data is None:
            return

        # Fill in parameters that will be set later in pytest_runtest_call hook,
        # otherwise pytest will raise unknown fixture error.
        if data.topology_mark is not None:
            # Make mh fixture always available
            if 'mh' not in item.fixturenames:
                item.fixturenames.append('mh')

            spec = inspect.getfullargspec(item.obj)
            for arg in data.topology_mark.args:
                if arg in spec.args:
                    item.funcargs[arg] = None

    @pytest.hookimpl(tryfirst=True)
    def pytest_runtest_call(self, item: pytest.Item) -> None:
        """
        Assign values to dynamically created multihost fixtures.

        :meta private:
        """

        data: MultihostItemData = item.multihost
        if data is None:
            return

        if data.topology_mark is not None:
            data.topology_mark.apply(item.funcargs['mh'], item.funcargs)

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item: pytest.Item, call: pytest.CallInfo[None]) -> pytest.TestReport | None:
        """
        Store test outcome in multihost data: item.multihost.outcome. The outcome
        can be 'passed', 'failed' or 'skipped'.
        """
        outcome = yield

        data: MultihostItemData = item.multihost
        result: pytest.TestReport = outcome.get_result()

        if result.when != 'call':
            return

        data.outcome = result.outcome

    def _fmt_color(self, text: str, color: str) -> str:
        if sys.stdout.isatty():
            reset = '\033[0m'
            return f'{color}{text}{reset}'

        return text

    def _fmt_bold(self, text: str) -> str:
        return self._fmt_color(text, '\033[1m')

    def _create_logger(self, verbose) -> logging.Logger:
        stdout = logging.StreamHandler(sys.stdout)
        stdout.setLevel(logging.DEBUG)
        stdout.setFormatter(logging.Formatter('%(message)s'))

        logger = self.GetLogger()
        logger.addHandler(stdout)
        logger.setLevel(logging.DEBUG if verbose else logging.INFO)

        return logger

    def _is_multihost_required(self, item: pytest.Item) -> bool:
        return item.get_closest_marker(name='topology') is not None

    def _can_run_test(self, item: pytest.Item, data: MultihostItemData | None) -> bool:
        if data is None:
            return not self._is_multihost_required(item)

        if data.topology_mark is not None:
            if self.exact_topology:
                if item.multihost.topology_mark.topology != self.topology:
                    return False
            else:
                if not self.topology.satisfies(item.multihost.topology_mark.topology):
                    return False

        return True

    def _clone_function(self, name: str, f: pytest.Function) -> pytest.Function:
        callspec = f.callspec if hasattr(f, 'callspec') else None

        return pytest.Function.from_parent(
            parent=f.parent,
            name=name,
            callspec=callspec,
            callobj=f.obj,
            keywords=f.keywords,
            fixtureinfo=f._fixtureinfo,
            originalname=f.originalname
        )


# These pytest hooks must be available outside of the plugin's class because
# they are executed before the plugin is registered.

def pytest_addoption(parser):
    """
    :meta private:
    """

    parser.addoption(
        "--exact-topology", action="store_true",
        help="Test will be deselected if its topology does not match multihost config exactly"
    )

    parser.addoption(
        "--mh-log-path", action="store", help="Path to store multihost logs"
    )

    parser.addoption(
        "--mh-config", action="store", help="Path to the multihost configuration file"
    )

    parser.addoption(
        "--mh-lazy-ssh", action="store_true", help="Hosts postpone connecting over SSH until it is required"
    )

    parser.addoption(
        "--collect-artifacts", action="store", default="on-failure", nargs="?",
        choices=["never", "on-failure", "always"],
        help="Collect artifacts after test run (default: %(default)s)"
    )

    parser.addoption(
        "--artifacts-dir", action="store", default="./artifacts",
        help="Directory where artifacts will be stored (default: %(default)s)"
    )


def pytest_configure(config: pytest.Config):
    """
    :meta private:
    """

    # register additional markers
    config.addinivalue_line(
        'markers',
        'topology(name: str, topology: lib.multihost.topology.Topology, domains: dict[str, str], /, '
        + '*, fixture1=target1, ...): topology required to run the test'
    )

    config.pluginmanager.register(MultihostPlugin(config))
