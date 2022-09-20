Crash Course
############

This is a crash course for SSSD's test framework. The course consists of
multiple task that show the fundamental features and API. First, try to find
the solution for the task by yourself using the information present in the
documentation and inside the hints. Then display the task's solution and compare
it with yours.

Prepare the environment
***********************

Our tests require multiple hosts to run. You can prepare the machines yourself
or you can use the `SSSD/sssd-ci-containers`_ project which is a combination of
containers (for the client and LDAP, IPA and Samba server) and vagrant virtual
machine (for Active Directory).

.. _SSSD/sssd-ci-containers: https://github.com/SSSD/sssd-ci-containers

Setup containers
================

.. code-block:: text

    $ git clone git@github.com:SSSD/sssd-ci-containers.git
    $ cd sssd-ci-containers
    $ sudo dnf install -y podman podman-docker docker-compose
    $ sudo systemctl enable --now podman.socket
    $ sudo setsebool -P container_manage_cgroup true
    $ cp env.example .env
    $ sudo make trust-ca
    $ sudo make setup-dns
    $ sudo make up

Setup Active Directory with vagrant
===================================

It is recommended (but not necessary) to use vagrant from
``quay.io/sssd/vagrant:latest`` container to avoid issues with plugin
installation.

.. code-block:: text

    $ sudo dnf remove -y vagrant
    # Add the following to ~/.bashrc and ‘source ~/.bashrc’
    function vagrant {
    dir="${VAGRANT_HOME:-$HOME/.vagrant.d}"
    mkdir -p "$dir/"{boxes,data,tmp}

    podman run -it --rm \
        -e LIBVIRT_DEFAULT_URI \
        -v /var/run/libvirt/:/var/run/libvirt/ \
        -v "$dir/boxes:/vagrant/boxes" \
        -v "$dir/data:/vagrant/data" \
        -v "$dir/tmp:/vagrant/tmp" \
        -v $(realpath "${PWD}"):${PWD} \
        -w $(realpath "${PWD}") \
        --network host \
        --security-opt label=disable \
        quay.io/sssd/vagrant:latest \
        vagrant $@
    }
    $ cd sssd-ci-containers/src
    $ vagrant up
    $ sudo podman exec client bash -c "echo vagrant | realm join ad.test"
    $ sudo podman exec client cp /etc/krb5.keytab /enrollment/ad.keytab
    $ sudo podman exec client rm /etc/krb5.keytab

Setup tests POC repo
====================

.. code-block:: text

    $ git clone https://github.com/pbrezina/sssd-tests-poc.git
    $ cd sssd-tests-poc
    $ python3 -m venv .venv
    $ source .venv/bin/activate
    $ pip3 install -r ./requirements.txt

Is everything working?
======================

You should be ready to execute the tests, if the steps above were all successful.

.. code-blocK:: text

    $ pytest --multihost-config ./mhc.yaml --multihost-log-path=./log -v ./tests/test_demo.py

Take the Course
***************

You can begin by creating a file inside the ``tests`` directory, for example
``tests/test_course.py`` and include the following imports:

.. code-block:: python

    import pytest

    from lib.multihost import KnownTopology, KnownTopologyGroup
    from lib.multihost.roles import AD, IPA, LDAP, Client, GenericADProvider, GenericProvider, Samba

Now try to run the file with ``pytest``:

.. code-block:: console

    pytest --multihost-config ./mhc.yaml --multihost-log-path=./log -v ./tests/test_course.py

Does it work? Good. Now, you can continue with the following tasks.

* Tasks 1 to 14 will teach you how to write some basic tests for LDAP.
* Tasks 15 - 26 requires you to write the same tests but for IPA. You will see
  that it is pretty much the same except some differences in primary group - IPA
  creates primary groups automatically.
* Tasks 26 - 31 are about topology parametrization - writing single test for
  multiple backends.

.. dropdown:: Task 1
    :color: secondary
    :icon: checklist

    Write your first test for the LDAP topology. The test does not have to do
    anything, just define it and make sure you can run it successfully.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :class:`lib.multihost.KnownTopology`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.LDAP)
            def test__01(client: Client, ldap: LDAP):
                pass

.. dropdown:: Task 2
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser``.
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ldap.LDAP`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.tools.HostTools`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.LDAP)
            def test__02(client: Client, ldap: LDAP):
                ldap.user('tuser').add()

                client.sssd.start()
                result = client.tools.id('tuser')
                assert result is not None
                assert result.user.name == 'tuser'

.. dropdown:: Task 3
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser`` with uid and gid set to ``10001``.
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid, gid.
    #. Also check that the primary group of the user does not exist.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopology``
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ldap.LDAP`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.tools.HostTools`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.LDAP)
            def test__03(client: Client, ldap: LDAP):
                ldap.user('tuser').add(uid=10001, gid=10001)

                client.sssd.start()
                result = client.tools.id('tuser')
                assert result is not None
                assert result.user.name == 'tuser'
                assert result.user.id == 10001
                assert result.group.name is None
                assert result.group.id == 10001

.. dropdown:: Task 4
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser`` with uid and gid set to ``10001``.
    #. Add new LDAP group named ``tuser`` with gid set to ``10001``.
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid,
       primary group name and gid.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ldap.LDAP`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.tools.HostTools`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.LDAP)
            def test__04(client: Client, ldap: LDAP):
                ldap.user('tuser').add(uid=10001, gid=10001)
                ldap.group('tuser').add(gid=10001)

                client.sssd.start()
                result = client.tools.id('tuser')
                assert result is not None
                assert result.user.name == 'tuser'
                assert result.user.id == 10001
                assert result.group.name == 'tuser'
                assert result.group.id == 10001

.. dropdown:: Task 5
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser`` with uid and gid set to ``10001``.
    #. Add new LDAP group named ``tuser`` with gid set to ``10001``.
    #. Add new LDAP group named ``users`` with gid set to ``20001``.
    #. Add user ``tuser`` as a member of group ``users``
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid,
       primary group name and gid.
    #. Check that the user is member of ``users``

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ldap.LDAP`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.tools.HostTools`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.LDAP)
            def test__05(client: Client, ldap: LDAP):
                u = ldap.user('tuser').add(uid=10001, gid=10001)
                ldap.group('tuser').add(gid=10001)
                ldap.group('users').add(gid=20001).add_member(u)

                client.sssd.start()
                result = client.tools.id('tuser')
                assert result is not None
                assert result.user.name == 'tuser'
                assert result.user.id == 10001
                assert result.group.name == 'tuser'
                assert result.group.id == 10001
                assert result.memberof('users')

        .. seealso::

            The memberof method allows you to use multiple input types. Including
            group name (string), group id (int) and list of names or ids.

.. dropdown:: Task 6
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser`` with uid and gid set to ``10001``.
    #. Add new LDAP group named ``tuser`` with gid set to ``10001``.
    #. Add two LDAP groups named ``users`` and ``admins`` without any gid set.
    #. Add user ``tuser`` as a member of groups ``users`` and ``admins``
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid,
       primary group name and gid.
    #. Check that the user is member of both ``users`` and ``admins``

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ldap.LDAP`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.tools.HostTools`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.LDAP)
            def test__06(client: Client, ldap: LDAP):
                u = ldap.user('tuser').add(uid=10001, gid=10001)
                ldap.group('tuser').add(gid=10001)
                ldap.group('users').add().add_member(u)
                ldap.group('admins').add().add_member(u)

                client.sssd.start()
                result = client.tools.id('tuser')
                assert result is not None
                assert result.user.name == 'tuser'
                assert result.user.id == 10001
                assert result.group.name == 'tuser'
                assert result.group.id == 10001
                assert result.memberof(['users', 'admins'])

        .. note::

            If you omit uid or gid attribute on user or group then the id is
            automatically generated by the framework. This is useful for cases where
            the id is not important.

.. dropdown:: Task 7
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser`` with password set to ``Secret123``.
    #. Start SSSD on the client.
    #. Test that the user can authenticate via ``su`` with the password.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-authentication`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ldap.LDAP`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.auth.HostAuthentication`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.LDAP)
            def test__07(client: Client, ldap: LDAP):
                ldap.user('tuser').add(password='Secret123')

                client.sssd.start()
                assert client.auth.su.password('tuser', 'Secret123')

        .. note::

            The password parameter defaults to ``Secret123`` so it can be omitted.
            However, it is a good practice to set it explicitly when you test
            authentication to help understand the test case.

.. dropdown:: Task 8
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser`` with password set to ``Secret123``.
    #. Start SSSD on the client.
    #. Test that the user can authenticate via ``ssh`` with the password.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-authentication`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ldap.LDAP`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.auth.HostAuthentication`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.LDAP)
            def test__08(client: Client, ldap: LDAP):
                ldap.user('tuser').add(password='Secret123')

                client.sssd.start()
                assert client.auth.ssh.password('tuser', 'Secret123')

.. dropdown:: Task 9
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Parametrize a test case argument with two values: ``su`` and ``ssh``
    #. Add new LDAP user named ``tuser`` with password set to ``Secret123``.
    #. Start SSSD on the client.
    #. Test that the user can authenticate via ``su`` and ``ssh`` with the password,
       use the parametrized value to determine which method should be used.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * `@pytest.mark.parametrize <https://docs.pytest.org/en/latest/how-to/parametrize.html>`__
        * :doc:`writing-tests`
        * :doc:`guides/testing-authentication`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ldap.LDAP`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.auth.HostAuthentication`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.LDAP)
            @pytest.mark.parametrize('method', ['su', 'ssh'])
            def test__09(client: Client, ldap: LDAP, method: str):
                ldap.user('tuser').add(password='Secret123')

                client.sssd.start()
                assert client.auth.parametrize(method).password('tuser', 'Secret123')

        .. note::

            This produces two test runs: one for ``su`` authentication and one for
            ``ssh``. It is better to parametrize the test instead of calling both
            ``su`` and ``ssh`` in one test run so you can test only one thing at a
            time if you ever need to debug failure.

.. dropdown:: Task 10
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser`` with password set to ``Secret123``.
    #. Add new sudo rule to LDAP that allows the user to run ``/bin/ls`` on ``ALL``
       hosts.
    #. Select ``sssd`` authselect profile with ``with-sudo`` enabled.
    #. Enable sudo responder in SSSD.
    #. Start SSSD on the client.
    #. Check that ``tuser`` can run only ``/bin/ls`` command and only as ``root``.
    #. Check that running ``/bin/ls`` through ``sudo`` actually works for ``tuser``.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-authentication`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ldap.LDAP`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.auth.HostAuthentication`
        * :class:`lib.multihost.utils.authselect.HostAuthselect`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.LDAP)
            def test__10(client: Client, ldap: LDAP):
                u = ldap.user('tuser').add(password='Secret123')
                ldap.sudorule('allow_ls').add(user=u, host='ALL', command='/bin/ls')

                client.authselect.select('sssd', ['with-sudo'])
                client.sssd.enable_responder('sudo')
                client.sssd.start()

                assert client.auth.sudo.list('tuser', 'Secret123', expected=['(root) /bin/ls'])
                assert client.auth.sudo.run('tuser', 'Secret123', command='/bin/ls /root')

        .. note::

            You need to enable ``with-sudo`` using authselect so sudo can read rules
            from SSSD.

.. dropdown:: Task 11
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser``.
    #. Add new sudo rule to LDAP that allows the user to run ``/bin/ls`` on ``ALL``
       hosts but without requiring authentication (nopasswd).
    #. Select ``sssd`` authselect profile with ``with-sudo`` enabled.
    #. Enable sudo responder in SSSD.
    #. Start SSSD on the client.
    #. Check that ``tuser`` can run only ``/bin/ls`` command without a password and only as ``root``.
    #. Check that running ``/bin/ls`` through ``sudo`` actually works for ``tuser`` without a password.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-authentication`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ldap.LDAP`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.auth.HostAuthentication`
        * :class:`lib.multihost.utils.authselect.HostAuthselect`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.LDAP)
            def test__11(client: Client, ldap: LDAP):
                u = ldap.user('tuser').add()
                ldap.sudorule('allow_ls').add(user=u, host='ALL', command='/bin/ls', nopasswd=True)

                client.authselect.select('sssd', ['with-sudo'])
                client.sssd.enable_responder('sudo')
                client.sssd.start()

                assert client.auth.sudo.list('tuser', expected=['(root) NOPASSWD: /bin/ls'])
                assert client.auth.sudo.run('tuser', command='/bin/ls /root')

.. dropdown:: Task 12
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser``.
    #. Set ``use_fully_qualified_names`` to ``true`` on the client.
    #. Start SSSD on the client.
    #. Check that ``tuser`` does not exist.
    #. Check that ``tuser@test`` exists.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ldap.LDAP`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.tools.HostTools`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.LDAP)
            def test__12(client: Client, ldap: LDAP):
                ldap.user('tuser').add()

                client.sssd.domain['use_fully_qualified_names'] = 'true'
                client.sssd.start()

                assert client.tools.id('tuser') is None
                assert client.tools.id('tuser@test') is not None

        .. note::

            Changes to the configuration are automatically applied when calling
            ``client.sssd.start()``. You can override this behavior by calling
            ``client.sssd.start(apply_config=False)``.

.. dropdown:: Task 13
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser``.
    #. Set ``use_fully_qualified_name`` to ``true`` on the client (intentionally
       create a typo in the option name).
    #. Start SSSD on the client.
    #. Assert that an ``Exception`` was risen

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * `pytest.raises <https://docs.pytest.org/en/7.1.x/how-to/assert.html#assertions-about-expected-exceptions>`__
        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ldap.LDAP`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.LDAP)
            def test__13(client: Client, ldap: LDAP):
                ldap.user('tuser').add()

                with pytest.raises(Exception):
                    client.sssd.domain['use_fully_qualified_name'] = 'true'
                    client.sssd.start()

        .. note::

            Starting SSSD with ``client.sssd.start()`` automatically validates
            configuration with ``sssctl config-check``. If the validation fails, it
            raises an exception. You can override this behavior by calling
            ``client.sssd.start(check_config=False)``.

.. dropdown:: Task 14
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser`` with uid and gid set to ``10001``.
    #. Add new LDAP group named ``tuser`` with gid set to ``10001``, use rfc2307bis schema.
    #. Add two LDAP groups named ``users`` and ``admins`` without any gid set, use rfc2307bis schema.
    #. Add user ``tuser`` as a member of groups ``users`` and ``admins``
    #. Set ``ldap_schema`` to ``rfc2307bis`` on the client
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid,
       primary group name and gid.
    #. Check that the user is member of both ``users`` and ``admins``

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ldap.LDAP`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.tools.HostTools`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.LDAP)
            def test__14(client: Client, ldap: LDAP):
                u = ldap.user('tuser').add(uid=10001, gid=10001)
                ldap.group('tuser', rfc2307bis=True).add(gid=10001)
                ldap.group('users', rfc2307bis=True).add().add_member(u)
                ldap.group('admins', rfc2307bis=True).add().add_member(u)

                client.sssd.domain['ldap_schema'] = 'rfc2307bis'
                client.sssd.start()

                result = client.tools.id('tuser')
                assert result is not None
                assert result.user.name == 'tuser'
                assert result.user.id == 10001
                assert result.group.name == 'tuser'
                assert result.group.id == 10001
                assert result.memberof(['users', 'admins'])

.. dropdown:: Task 15
    :color: secondary
    :icon: checklist

    Write your first test for the IPA topology. The test does not have to do
    anything, just define it and make sure you can run it successfully.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :class:`lib.multihost.KnownTopology`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.IPA)
            def test__15(client: Client, ipa: IPA):
                pass

.. dropdown:: Task 16
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser``.
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ipa.IPA`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.tools.HostTools`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.IPA)
            def test__16(client: Client, ipa: IPA):
                ipa.user('tuser').add()

                client.sssd.start()
                result = client.tools.id('tuser')
                assert result is not None
                assert result.user.name == 'tuser'

.. dropdown:: Task 17
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser`` with uid and gid set to ``10001``.
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid,
       primary group name and gid.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ipa.IPA`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.tools.HostTools`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.IPA)
            def test__17(client: Client, ipa: IPA):
                ipa.user('tuser').add(uid=10001, gid=10001)

                client.sssd.start()
                result = client.tools.id('tuser')
                assert result is not None
                assert result.user.name == 'tuser'
                assert result.user.id == 10001
                assert result.group.name == 'tuser'
                assert result.group.id == 10001

        .. note::

            Unlike LDAP, IPA creates the primary group automatically therefore we do
            not have to add it ourselves.

.. dropdown:: Task 18
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser`` with uid and gid set to ``10001``.
    #. Add new IPA group named ``users`` with gid set to ``20001``.
    #. Add user ``tuser`` as a member of group ``users``
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid,
       primary group name and gid.
    #. Check that the user is member of ``users``

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ipa.IPA`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.tools.HostTools`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.IPA)
            def test__18(client: Client, ipa: IPA):
                u = ipa.user('tuser').add(uid=10001, gid=10001)
                ipa.group('users').add(gid=20001).add_member(u)

                client.sssd.start()
                result = client.tools.id('tuser')
                assert result is not None
                assert result.user.name == 'tuser'
                assert result.user.id == 10001
                assert result.group.name == 'tuser'
                assert result.group.id == 10001
                assert result.memberof('users')

.. dropdown:: Task 19
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser`` with uid and gid set to ``10001``.
    #. Add new IPA group named ``users`` without any gid set.
    #. Create a group object for IPA group ``admins`` that already exist (it is created by IPA installation)
    #. Add user ``tuser`` as a member of groups ``users`` and ``admins``
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid,
       primary group name and gid.
    #. Check that the user is member of both ``users`` and ``admins``

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ipa.IPA`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.tools.HostTools`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.IPA)
            def test__19(client: Client, ipa: IPA):
                u = ipa.user('tuser').add(uid=10001, gid=10001)
                ipa.group('users').add().add_member(u)
                ipa.group('admins').add_member(u)

                client.sssd.start()
                result = client.tools.id('tuser')
                assert result is not None
                assert result.user.name == 'tuser'
                assert result.user.id == 10001
                assert result.group.name == 'tuser'
                assert result.group.id == 10001
                assert result.memberof(['users', 'admins'])

.. dropdown:: Task 20
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser`` with password set to ``Secret123``.
    #. Start SSSD on the client.
    #. Test that the user can authenticate via ``su`` with the password.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-authentication`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ipa.IPA`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.auth.HostAuthentication`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.IPA)
            def test__10(client: Client, ipa: IPA):
                ipa.user('tuser').add(password='Secret123')

                client.sssd.start()
                assert client.auth.su.password('tuser', 'Secret123')

.. dropdown:: Task 21
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser`` with password set to ``Secret123``.
    #. Start SSSD on the client.
    #. Test that the user can authenticate via ``ssh`` with the password.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-authentication`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ipa.IPA`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.auth.HostAuthentication`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.IPA)
            def test__21(client: Client, ipa: IPA):
                ipa.user('tuser').add(password='Secret123')

                client.sssd.start()
                assert client.auth.ssh.password('tuser', 'Secret123')

.. dropdown:: Task 22
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Parametrize a test case argument with two values: ``su`` and ``ssh``
    #. Add new IPA user named ``tuser`` with password set to ``Secret123``.
    #. Start SSSD on the client.
    #. Test that the user can authenticate via ``su`` and ``ssh`` with the password,
       use the parametrized value to determine which method should be used.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * `@pytest.mark.parametrize <https://docs.pytest.org/en/latest/how-to/parametrize.html>`__
        * :doc:`writing-tests`
        * :doc:`guides/testing-authentication`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ipa.IPA`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.auth.HostAuthentication`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.IPA)
            @pytest.mark.parametrize('method', ['su', 'ssh'])
            def test__22(client: Client, ipa: IPA, method: str):
                ipa.user('tuser').add(password='Secret123')

                client.sssd.start()
                assert client.auth.parametrize(method).password('tuser', 'Secret123')

.. dropdown:: Task 23
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser`` with password set to ``Secret123``.
    #. Add new sudo rule to IPA that allows the user to run ``/bin/ls`` on ``ALL``
       hosts.
    #. Select ``sssd`` authselect profile with ``with-sudo`` enabled.
    #. Enable sudo responder in SSSD.
    #. Start SSSD on the client.
    #. Check that ``tuser`` can run only ``/bin/ls`` command and only as ``root``.
    #. Check that running ``/bin/ls`` through ``sudo`` actually works for ``tuser``.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-authentication`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ipa.IPA`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.auth.HostAuthentication`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.IPA)
            def test__23(client: Client, ipa: IPA):
                u = ipa.user('tuser').add(password='Secret123')
                ipa.sudorule('allow_ls').add(user=u, host='ALL', command='/bin/ls')

                client.authselect.select('sssd', ['with-sudo'])
                client.sssd.enable_responder('sudo')
                client.sssd.start()

                assert client.auth.sudo.list('tuser', 'Secret123', expected=['(root) /bin/ls'])
                assert client.auth.sudo.run('tuser', 'Secret123', command='/bin/ls /root')

.. dropdown:: Task 24
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser``.
    #. Add new sudo rule to IPA that allows the user to run ``/bin/ls`` on ``ALL``
       hosts but without requiring authentication (nopasswd).
    #. Select ``sssd`` authselect profile with ``with-sudo`` enabled.
    #. Enable sudo responder in SSSD.
    #. Start SSSD on the client.
    #. Check that ``tuser`` can run only ``/bin/ls`` command without a password and only as ``root``.
    #. Check that running ``/bin/ls`` through ``sudo`` actually works for ``tuser`` without a password.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-authentication`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ipa.IPA`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.auth.HostAuthentication`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.IPA)
            def test__24(client: Client, ipa: IPA):
                u = ipa.user('tuser').add()
                ipa.sudorule('allow_ls').add(user=u, host='ALL', command='/bin/ls', nopasswd=True)

                client.authselect.select('sssd', ['with-sudo'])
                client.sssd.enable_responder('sudo')
                client.sssd.start()

                assert client.auth.sudo.list('tuser', expected=['(root) NOPASSWD: /bin/ls'])
                assert client.auth.sudo.run('tuser', command='/bin/ls /root')

.. dropdown:: Task 25
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser``.
    #. Set ``use_fully_qualified_names`` to ``true`` on the client.
    #. Start SSSD on the client.
    #. Check that ``tuser`` does not exist.
    #. Check that ``tuser@test`` exists.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ipa.IPA`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.tools.HostTools`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.IPA)
            def test__25(client: Client, ipa: IPA):
                ipa.user('tuser').add()

                client.sssd.domain['use_fully_qualified_names'] = 'true'
                client.sssd.start()

                assert client.tools.id('tuser') is None
                assert client.tools.id('tuser@test') is not None

.. dropdown:: Task 26
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser``.
    #. Set ``use_fully_qualified_name`` to ``true`` on the client (intentionally
       create a typo in the option name).
    #. Start SSSD on the client.
    #. Assert that an ``Exception`` was risen

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopology`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.ldap.LDAP`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.IPA)
            def test__26(client: Client, ipa: IPA):
                ipa.user('tuser').add()

                with pytest.raises(Exception):
                    client.sssd.domain['use_fully_qualified_name'] = 'true'
                    client.sssd.start()

.. dropdown:: Task 27
    :color: secondary
    :icon: checklist

    #. Create a new parametrized test for LDAP, IPA, Samba and AD topology.
    #. Add new user named ``tuser``.
    #. Add new groups ``tgroup_1`` and ``tgroup_2``
    #. Add the user ``tuser`` as a member of ``tgroup_1`` and ``tgroup_2``
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name.
    #. Check that the user is member of ``tgroup_1`` and ``tgroup_2``

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopologyGroup`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.generic.GenericProvider`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.tools.HostTools`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
            def test__27(client: Client, provider: GenericProvider):
                u = provider.user('tuser').add()
                provider.group('tgroup_1').add().add_member(u)
                provider.group('tgroup_2').add().add_member(u)

                client.sssd.start()
                result = client.tools.id('tuser')

                assert result is not None
                assert result.user.name == 'tuser'
                assert result.memberof(['tgroup_1', 'tgroup_2'])

        .. note::

            We can write single test that can be run on multiple topologies. This is
            achieved by using well-defined API that is implemented by all providers.
            However, there are some distinctions that you need to be aware of - for
            example LDAP does not create primary group automatically, IPA creates it
            automatically and Samba and AD uses ``Domain Users`` as the primary
            group.

.. dropdown:: Task 28
    :color: secondary
    :icon: checklist

    #. Create a new parametrized test for Samba and AD topology.
    #. Add new user named ``tuser``.
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name.
    #. Check that the user is member of ``domain users`` (Active Directory built-in group)

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopologyGroup`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.generic.GenericADProvider`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.tools.HostTools`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopologyGroup.AnyAD)
            def test__28(client: Client, provider: GenericADProvider):
                provider.user('tuser').add()

                client.sssd.start()
                result = client.tools.id('tuser')

                assert result is not None
                assert result.user.name == 'tuser'
                assert result.group.name.lower() == 'domain users'

.. dropdown:: Task 29
    :color: secondary
    :icon: checklist

    #. Create a new parametrized test for LDAP and IPA topology.
    #. Add new user named ``tuser`` with uid and gid set to ``10001``.
    #. Create user's primary group object only if the topology is LDAP
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid,
       primary group name and gid.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-identity`
        * :class:`lib.multihost.KnownTopologyGroup`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.generic.GenericProvider`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.tools.HostTools`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.LDAP)
            @pytest.mark.topology(KnownTopology.IPA)
            def test__29(client: Client, provider: GenericProvider):
                provider.user('tuser').add(uid=10001, gid=10001)

                if isinstance(provider, LDAP):
                    provider.group('tuser').add(gid=10001)

                client.sssd.start()
                result = client.tools.id('tuser')
                assert result is not None
                assert result.user.name == 'tuser'
                assert result.user.id == 10001
                assert result.group.name == 'tuser'
                assert result.group.id == 10001

.. dropdown:: Task 30
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP, IPA and AD topology.
    #. Add new user named ``tuser``.
    #. Add new sudo rule ``defaults`` and set ``!authenticate`` option
    #. Add new sudo rule to that ``ALL`` users on ``ALL`` hosts run ``ALL`` commands.
    #. Select ``sssd`` authselect profile with ``with-sudo`` enabled.
    #. Enable sudo responder in SSSD.
    #. Start SSSD on the client.
    #. Check that ``tuser`` can run ``ALL`` commands without a password but only as ``root``.
    #. Check that running ``/bin/ls`` through ``sudo`` actually works for ``tuser`` without a password.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`writing-tests`
        * :doc:`guides/testing-authentication`
        * :class:`lib.multihost.KnownTopologyGroup`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.generic.GenericProvider`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.auth.HostAuthentication`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.LDAP)
            @pytest.mark.topology(KnownTopology.IPA)
            @pytest.mark.topology(KnownTopology.AD)
            def test__30(client: Client, provider: GenericProvider):
                u = provider.user('tuser').add()
                provider.sudorule('defaults').add(nopasswd=True)
                provider.sudorule('allow_all').add(user='ALL', host='ALL', command='ALL')

                client.authselect.select('sssd', ['with-sudo'])
                client.sssd.enable_responder('sudo')
                client.sssd.start()

                assert client.auth.sudo.list('tuser', expected=['(root) ALL'])
                assert client.auth.sudo.run('tuser', command='/bin/ls /root')

.. dropdown:: Task 31
    :color: secondary
    :icon: checklist

    #. Create a new parametrized test for LDAP, IPA, Samba and AD topology.
    #. Parametrize a test case argument with two values: ``su`` and ``ssh``
    #. Add new user named ``tuser`` with password set to ``Secret123``.
    #. Start SSSD on the client.
    #. Test that the user can authenticate via ``su`` and ``ssh`` with the password,
       use the parametrized value to determine which method should be used.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * `@pytest.mark.parametrize <https://docs.pytest.org/en/latest/how-to/parametrize.html>`__
        * :doc:`writing-tests`
        * :doc:`guides/testing-authentication`
        * :class:`lib.multihost.KnownTopologyGroup`
        * :class:`lib.multihost.roles.base.LinuxRole`
        * :class:`lib.multihost.roles.generic.GenericProvider`
        * :class:`lib.multihost.roles.client.Client`
        * :class:`lib.multihost.utils.sssd.HostSSSD`
        * :class:`lib.multihost.utils.auth.HostAuthentication`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

            @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
            @pytest.mark.parametrize('method', ['su', 'ssh'])
            def test__31(client: Client, provider: GenericProvider, method: str):
                provider.user('tuser').add(password='Secret123')

                client.sssd.start()
                assert client.auth.parametrize(method).password('tuser', 'Secret123')
