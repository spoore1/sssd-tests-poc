from __future__ import annotations

import pytest

from lib.multihost import KnownTopology
from lib.multihost.roles import LDAP, Client, GenericProvider


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_lookup_domain_user_in_sso(client: Client, provider: GenericProvider):
    """
    :title: Lookup domain user in sso
    :id: <UUID>
    :steps:
        1. add user to domain
            # ipa user-add
        2. lookup user in SSO
            # alias kcadm='sudo podman exec -it kite-keycloak /opt/keycloak/bin/kcadm.sh'
            # kcadm config credentials \
                --server https://master.keycloak.test:8443/auth/ \
                --realm master --user admin --password Secret123
            # kcadm get users -q username=ipauser1  
    :expectedresults:
        1. null
        2. user found in SSO
            # need to parse json output
    """
    pass


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_lookup_sso_user_in_domain(client: Client, provider: GenericProvider):
    """
    :title: Lookup sso user in domain
    :id: <UUID>
    :steps:
        1. add user to SSO
            # kcadm create users -r master \
                -s username=kcuser1 \
                -s enabled=true \
                -s email=kcuser1@ipa.test
        2. lookup user in domain
            # ipa user-show kcuser1
    :expectedresults:
        1. null
        2. user found in domain
            # returns id info
    """
    pass

@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_authn_as_domain_user_in_sso(client: Client, provider: GenericProvider):
    """
    :title: Authenticate as domain user in SSO
    :id: <UUID>
    :steps:
        1. add user in domain
            # ipa user-add ipauser1 --first=f --last=l --password
            # kinit ipauser1
        2. authenticate as user in SSO via web page login
            # kcadm config credentials \
                --server https://master.keycloak.test:8443/auth/ \
                --realm master --user ipauser1 --password Secret123
    :expectedresults:
        1. null
        2. authentication succeeds
            # returns:
                Logging into https://master.keycloak.test:8443/auth/ as \
                user ipauser1 of realm master
    """
    pass


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize('method', ['su', 'ssh'])
def test_authn_as_sso_user_in_domain(client: Client, provider: GenericProvider):
    """
    :title: Authenticate as SSO user in domain
    :id: <UUID>
    :steps:
        1. add user in SSO
            # kcadm create users -r master \
                -s username=kcuser1 \
                -s enabled=true \
                -s email=kcuser1@ipa.test
        2. Set SSO User password in Domain
            # ipa password kcuser1
            # kinit kcuser1
        3. authenticate as user in domain
            # su - kcuser1 -c 'su - kcuser1 -c whoami'
    :expectedresults:
        1. null
        2. null
        3. authentication succeeds
            # returns kcuser1
    """
    pass


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_manage_sso_user_crud(client: Client, provider: GenericProvider):
    """
    :title: Manage SSO user add modify delete
    :id: <UUID>
    :steps:
        1. add user in SSO
            # kcadm create users -r master \
                -s username=kcuser1 \
                -s enabled=true \
                -s email=kcuser1@ipa.test
        2. check user in domain
            # ipa user-show kcuser1
        3. change user attribute in SSO
            # kcadm update users/<ID> \
                -s lastName=fixed123
        4. check change reflected in domain
            # ipa user-show kcuser1
        5. delete user in SSO
            # kcadm delete users/<ID>
        6. check user removed from domain
            # ipa user-show kcuser1
    :expectedresults:
        1. null
        2. user visble in domain
        3. null
        4. attribute change reflected in domain
        5. null
        6. user no longer visible in domain
    """
    pass


@pytest.mark.skip(reason="SSO group replication not yet supported")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_manage_sso_group_crud(client: Client, provider: GenericProvider):
    """
    :title: Manage SSO group add modify delete
    :id: <UUID>
    :steps:
        1. add group in SSO
            # kcadm create groups -r master -s name=<groupname>
        2. check group in domain
            # ipa group-show <groupname>
        3. add user to group in SSO
        4. check user in group in domain
        5. remove user from group in SSO
        6. check user removed from group in domain
        7. delete group in SSO
        8. check group removed from domain
    :expectedresults:
        1. null
        2. user visble in domain
        3. null
        4. user visible in group in domain
        5. null
        6. user no longer visible in group in domain
        7. null
        8. user no longer visible in domain
    """
    pass


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_manage_domain_user_crud(client: Client, provider: GenericProvider):
    """
    :title: Manage domain user add modify delete
    :id: <UUID>
    :steps:
        1. Add user in domain
        2. check user in SSO
        3. change user attribute in domain
        4. check change reflected in SSO
        5. delete user in domain
        6. check user removed from SSO
    :expectedresults:
        1. null
        2. user visble in SSO
        3. null
        4. attribute change reflected in SSO
        5. null
        6. user no longer visible in SSO
    """
    pass


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_manage_domain_group_crud(client: Client, provider: GenericProvider):
    """
    :title: Manage domain group add modify delete
    :id: <UUID>
    :steps:
        1. add group in domain
        2. check group in SSO
        3. add user to group in domain
        4. check user in group in SSO
        5. remove user from group in domain
        6. check user removed from group in SSO
        7. delete user in domain
        8. check user removed from SSO
    :expectedresults:
        1. null
        2. user visble in domain
        3. null
        4. user visible in group in domain
        5. null
        6. user no longer visible in group in domain
        7. null
        8. user no longer visible in domain
    """
    pass


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_testname(client: Client, provider: GenericProvider):
    """
    :title: <TITLE>
    :id: <UUID>
    :steps:
        1. 
    :expectedresults:
        1. null
    """
    pass