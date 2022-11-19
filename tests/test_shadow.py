from __future__ import annotations

import pytest

from lib.multihost import KnownTopology, Multihost, Topology, TopologyDomain
from lib.multihost.roles import LDAP, Client


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize('method', ['su', 'ssh'])
def test_0001_BZ1507035(client: Client, ldap: LDAP, method: str):
    """
    :title: SSSD does not support to change the user’s password when option ldap_pwd_policy equals to shadow in
    sssd.conf file
    :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1507035
    :id: 4104ff75-7fab-4344-858f-b1762b6e5aaa
    :steps:
        1. Create the shadowuser1 with shadow parameters
        2. Add ldap_pwd_policy = shadow and ldap_chpass_update_last_change = True in sssd.conf
        3. Change the user's password as password is expired
        4. Login to the same user with changed password.
    :expectedresults:
        1. Successfully create the shadowuser1
        2. Successfully update the sssd.conf
        3. Successfully change the user's password.
        4. Successfully login to the same user with newly changed password.
     """
    # Add aci entry
    ldap.aci.add('(targetattr="userpassword")(version 3.0; acl "pwp test"; allow (all) userdn="ldap:///self";)')

    # Disabling pam_id_timeout makes the test pass,
    # after verifying the BZ2144893, will remove below line.
    client.sssd.pam['pam_id_timeout'] = '0'

    # Add extra attributes in domain section
    client.sssd.domain['ldap_pwd_policy'] = 'shadow'
    client.sssd.domain['ldap_chpass_update_last_change'] = 'True'
    client.sssd.start()

    # Create shadowuser user
    ldap.user('shadowuser1').add(uid=999011, gid=999011, shadowMin=0, shadowMax=99999,
                                 shadowWarning=7, shadowLastChange=0, password='Secret123')

    # Change the user password as password is expired
    assert client.auth.parametrize(method).password_expired('shadowuser1', 'Secret123', 'Redhat@321')

    # Check auth again with changed password
    assert client.auth.parametrize(method).password('shadowuser1', 'Redhat@321')
