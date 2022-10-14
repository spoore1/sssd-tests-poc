from __future__ import annotations

import pytest

from lib.multihost import KnownTopology, KnownTopologyGroup
from lib.multihost.roles import IPA, LDAP, Client, GenericADProvider, GenericProvider


@pytest.mark.topology(KnownTopology.LDAP)
def test__01(client: Client, ldap: LDAP):
    pass


@pytest.mark.topology(KnownTopology.LDAP)
def test__02(client: Client, ldap: LDAP):
    ldap.user('tuser').add()

    client.sssd.start()
    result = client.tools.id('tuser')
    assert result is not None
    assert result.user.name == 'tuser'


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


@pytest.mark.topology(KnownTopology.LDAP)
def test__07(client: Client, ldap: LDAP):
    ldap.user('tuser').add(password='Secret123')

    client.sssd.start()
    assert client.auth.su.password('tuser', 'Secret123')


@pytest.mark.topology(KnownTopology.LDAP)
def test__08(client: Client, ldap: LDAP):
    ldap.user('tuser').add(password='Secret123')

    client.sssd.start()
    assert client.auth.ssh.password('tuser', 'Secret123')


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize('method', ['su', 'ssh'])
def test__09(client: Client, ldap: LDAP, method: str):
    ldap.user('tuser').add(password='Secret123')

    client.sssd.start()
    assert client.auth.parametrize(method).password('tuser', 'Secret123')


@pytest.mark.topology(KnownTopology.LDAP)
def test__10(client: Client, ldap: LDAP):
    u = ldap.user('tuser').add(password='Secret123')
    ldap.sudorule('allow_ls').add(user=u, host='ALL', command='/bin/ls')

    client.authselect.select('sssd', ['with-sudo'])
    client.sssd.enable_responder('sudo')
    client.sssd.start()

    assert client.auth.sudo.list('tuser', 'Secret123', expected=['(root) /bin/ls'])
    assert client.auth.sudo.run('tuser', 'Secret123', command='/bin/ls /root')


@pytest.mark.topology(KnownTopology.LDAP)
def test__11(client: Client, ldap: LDAP):
    u = ldap.user('tuser').add()
    ldap.sudorule('allow_ls').add(user=u, host='ALL', command='/bin/ls', nopasswd=True)

    client.authselect.select('sssd', ['with-sudo'])
    client.sssd.enable_responder('sudo')
    client.sssd.start()

    assert client.auth.sudo.list('tuser', expected=['(root) NOPASSWD: /bin/ls'])
    assert client.auth.sudo.run('tuser', command='/bin/ls /root')


@pytest.mark.topology(KnownTopology.LDAP)
def test__12(client: Client, ldap: LDAP):
    ldap.user('tuser').add()

    client.sssd.domain['use_fully_qualified_names'] = 'true'
    client.sssd.start()

    assert client.tools.id('tuser') is None
    assert client.tools.id('tuser@test') is not None


@pytest.mark.topology(KnownTopology.LDAP)
def test__13(client: Client, ldap: LDAP):
    ldap.user('tuser').add()

    with pytest.raises(Exception):
        client.sssd.domain['use_fully_qualified_name'] = 'true'
        client.sssd.start()


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


@pytest.mark.topology(KnownTopology.IPA)
def test__15(client: Client, ipa: IPA):
    pass


@pytest.mark.topology(KnownTopology.IPA)
def test__16(client: Client, ipa: IPA):
    ipa.user('tuser').add()

    client.sssd.start()
    result = client.tools.id('tuser')
    assert result is not None
    assert result.user.name == 'tuser'


@pytest.mark.topology(KnownTopology.IPA)
def test__17(client: Client, ipa: IPA):
    ipa.user('tuser').add(uid=10001, gid=10001)

    # Primary group is created automatically, we need to skip this step
    # ipa.group('tuser').add(gid=10001)

    client.sssd.start()
    result = client.tools.id('tuser')
    assert result is not None
    assert result.user.name == 'tuser'
    assert result.user.id == 10001
    assert result.group.name == 'tuser'
    assert result.group.id == 10001


@pytest.mark.topology(KnownTopology.IPA)
def test__18(client: Client, ipa: IPA):
    u = ipa.user('tuser').add(uid=10001, gid=10001)
    # Primary group is created automatically, we need to skip this step
    # ipa.group('tuser').add(gid=10001)
    ipa.group('users').add(gid=20001).add_member(u)

    client.sssd.start()
    result = client.tools.id('tuser')
    assert result is not None
    assert result.user.name == 'tuser'
    assert result.user.id == 10001
    assert result.group.name == 'tuser'
    assert result.group.id == 10001
    assert result.memberof('users')


@pytest.mark.topology(KnownTopology.IPA)
def test__19(client: Client, ipa: IPA):
    u = ipa.user('tuser').add(uid=10001, gid=10001)
    # Primary group is created automatically, we need to skip this step
    # ipa.group('tuser').add(gid=10001)
    ipa.group('users').add().add_member(u)
    # Group admins is already present in IPA so we just omit add() and use add_member() only
    # ipa.group('admins').add().add_member(u)
    ipa.group('admins').add_member(u)

    client.sssd.start()
    result = client.tools.id('tuser')
    assert result is not None
    assert result.user.name == 'tuser'
    assert result.user.id == 10001
    assert result.group.name == 'tuser'
    assert result.group.id == 10001
    assert result.memberof(['users', 'admins'])


@pytest.mark.topology(KnownTopology.IPA)
def test__20(client: Client, ipa: IPA):
    ipa.user('tuser').add(password='Secret123')

    client.sssd.start()
    assert client.auth.su.password('tuser', 'Secret123')


@pytest.mark.topology(KnownTopology.IPA)
def test__21(client: Client, ipa: IPA):
    ipa.user('tuser').add(password='Secret123')

    client.sssd.start()
    assert client.auth.ssh.password('tuser', 'Secret123')


@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.parametrize('method', ['su', 'ssh'])
def test__22(client: Client, ipa: IPA, method: str):
    ipa.user('tuser').add(password='Secret123')

    client.sssd.start()
    assert client.auth.parametrize(method).password('tuser', 'Secret123')


@pytest.mark.topology(KnownTopology.IPA)
def test__23(client: Client, ipa: IPA):
    u = ipa.user('tuser').add(password='Secret123')
    ipa.sudorule('allow_ls').add(user=u, host='ALL', command='/bin/ls')

    client.authselect.select('sssd', ['with-sudo'])
    client.sssd.enable_responder('sudo')
    client.sssd.start()

    assert client.auth.sudo.list('tuser', 'Secret123', expected=['(root) /bin/ls'])
    assert client.auth.sudo.run('tuser', 'Secret123', command='/bin/ls /root')


@pytest.mark.topology(KnownTopology.IPA)
def test__24(client: Client, ipa: IPA):
    u = ipa.user('tuser').add()
    ipa.sudorule('allow_ls').add(user=u, host='ALL', command='/bin/ls', nopasswd=True)

    client.authselect.select('sssd', ['with-sudo'])
    client.sssd.enable_responder('sudo')
    client.sssd.start()

    assert client.auth.sudo.list('tuser', expected=['(root) NOPASSWD: /bin/ls'])
    assert client.auth.sudo.run('tuser', command='/bin/ls /root')


@pytest.mark.topology(KnownTopology.IPA)
def test__25(client: Client, ipa: IPA):
    ipa.user('tuser').add()

    client.sssd.domain['use_fully_qualified_names'] = 'true'
    client.sssd.start()

    assert client.tools.id('tuser') is None
    assert client.tools.id('tuser@test') is not None


@pytest.mark.topology(KnownTopology.IPA)
def test__26(client: Client, ipa: IPA):
    ipa.user('tuser').add()

    with pytest.raises(Exception):
        client.sssd.domain['use_fully_qualified_name'] = 'true'
        client.sssd.start()


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


@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test__28(client: Client, provider: GenericADProvider):
    provider.user('tuser').add()

    client.sssd.start()
    result = client.tools.id('tuser')

    assert result is not None
    assert result.user.name == 'tuser'
    assert result.group.name.lower() == 'domain users'


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


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test__30(client: Client, provider: GenericProvider):
    provider.user('tuser').add()
    provider.sudorule('defaults').add(nopasswd=True)
    provider.sudorule('allow_all').add(user='ALL', host='ALL', command='ALL')

    client.authselect.select('sssd', ['with-sudo'])
    client.sssd.enable_responder('sudo')
    client.sssd.start()

    assert client.auth.sudo.list('tuser', expected=['(root) ALL'])
    assert client.auth.sudo.run('tuser', command='/bin/ls /root')


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize('method', ['su', 'ssh'])
def test__31(client: Client, provider: GenericProvider, method: str):
    provider.user('tuser').add(password='Secret123')

    client.sssd.start()
    assert client.auth.parametrize(method).password('tuser', 'Secret123')
