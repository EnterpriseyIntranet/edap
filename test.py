import os
import sys
from os.path import dirname
from os.path import join
import collections
import ldap

import pytest

sys.path.insert(0, join(dirname(__file__), 'src'))

from edap import Edap, ConstraintError, get_single_object, ldap_tuple_to_object, import_data, ObjectDoesNotExist, \
    MultipleObjectsFound, get_not_matching_teams_by_cn, get_not_matching_teams_by_description, ensure_org_sanity

DOMAIN = os.environ.get("DOMAIN")
ADMIN_CN = "cn=admin"
ADMIN_PASSWORD = os.environ.get("LDAP_ADMIN_PASSWORD")


@pytest.fixture(scope="session")
def edap():
    edap = Edap("ldap", ADMIN_CN, ADMIN_PASSWORD, DOMAIN)
    yield edap
    edap.ldap.unbind_s()


def test_extract_division():
    assert import_data.extract_division("foobar") is None
    assert import_data.extract_division("division-foo@example.com") == "foo"
    assert import_data.extract_division("team-cz-it@example.com") == "it"
    assert import_data.extract_division("ddea-edu@example.com") == "edu"


def test_extract_country():
    assert import_data.extract_country("foobar") is None
    assert import_data.extract_country("country-foo@example.com") == "foo"
    assert import_data.extract_country("team-cz-it@example.com") == "cz"
    assert import_data.extract_country("cdea-at@example.com") == "at"


def test_assign_membership():
    countries = collections.defaultdict(set)
    divisions = collections.defaultdict(set)

    import_data.assign_membership("user2", "foobar@example.com", countries, divisions)
    assert not divisions
    assert not countries

    import_data.assign_membership("user1", "team-cz-edu@example.com", countries, divisions)
    assert "user1" in divisions["edu"]
    assert "user1" in countries["cz"]

    import_data.assign_membership("user3", "cdea-cz@example.com", countries, divisions)
    assert "user3" in countries["cz"]

    import_data.assign_membership("user4", "ddea-fin@example.com", countries, divisions)
    assert "user4" in divisions["fin"]


def test_get_groups(edap):
    """ Test LdapGroupMixin get_groups, get_group methods """
    group_name = "test_group"
    org_unit_name = 'test_org_unit'
    assert len(edap.get_groups(search=f'cname={group_name}')) == 0
    res = edap.create_group(group_name, org_unit_name)
    assert len(edap.get_groups(search=f'cn={group_name}')) == 1
    assert edap.get_groups(search=f'cn={group_name}')[0] == edap.get_group(group_name, org_unit_name)


def test_blank(edap):
    assert not edap.subobject_exists_at(f"ou=people", "organizationalUnit")
    edap.create_org_unit("people")
    assert edap.subobject_exists_at("ou=people", "organizationalUnit",)
    assert not edap.subobject_exists_at("ou=people", "foobar")
    edap.delete_org_unit("people")
    assert not edap.subobject_exists_at("ou=people", "organizationalUnit",)


def test_divisions_becomes_present(edap):
    assert not edap.org_unit_exists("divisions")
    edap.create_org_unit("divisions")
    assert edap.org_unit_exists("divisions")
    edap.delete_org_unit("divisions")
    assert not edap.org_unit_exists("divisions")


def test_special_becomes_present(edap):
    assert not edap.org_unit_exists("special")
    edap.create_org_unit("special")
    assert edap.org_unit_exists("special")
    edap.delete_org_unit("special")
    assert not edap.subobject_exists_at("ou=special", "organizationalUnit",)


def test_presidium_special_becomes_present(edap):
    description = b'Presidium'
    presidium = "presidium"
    assert not edap.object_exists_at(f"cn={presidium},{edap.SPECIAL_GROUP}", "posixGroup")
    edap.create_special(machine_name=presidium, display_name="Presidium")
    assert edap.object_exists_at(f"cn={presidium},{edap.SPECIAL_GROUP}", "posixGroup")
    res = edap.get_special(presidium)
    assert description in res['description']


def test_ddea_becomes_present(edap):
    assert not edap.org_unit_exists("ddea")
    edap.create_org_unit("ddea")
    assert edap.org_unit_exists("ddea")
    edap.delete_org_unit("ddea")
    assert not edap.subobject_exists_at("ou=ddea", "organizationalUnit",)


def test_it_ddea_becomes_present(edap):
    description = b'IT Division Director'
    DDEA_IT_GROUP_DN = f"cn=it,{edap.DDEA_GROUP}"

    assert not edap.object_exists_at(DDEA_IT_GROUP_DN, "posixGroup")
    edap.create_ddea("it", display_name="IT Division Director")
    assert edap.object_exists_at(DDEA_IT_GROUP_DN, "posixGroup")
    res = edap.get_ddea("it")
    assert description in res['description']


def test_cdea_becomes_present(edap):
    assert not edap.org_unit_exists("cdea")
    edap.create_org_unit("cdea")
    assert edap.org_unit_exists("cdea")
    edap.delete_org_unit("cdea")
    assert not edap.subobject_exists_at("ou=cdea", "organizationalUnit",)


def test_cz_cdea_becomes_present(edap):
    description = b'Czechia'
    assert not edap.object_exists_at(f"cn=cz,{edap.CDEA_GROUP}", "posixGroup")
    edap.create_cdea(machine_name="cz", display_name="Czechia")
    assert edap.object_exists_at(f"cn=cz,{edap.CDEA_GROUP}", "posixGroup")
    res = edap.get_cdea("cz")
    assert description in res['description']


def test_lm_becomes_present(edap):
    assert not edap.org_unit_exists("lm")
    edap.create_org_unit("lm")
    assert edap.org_unit_exists("lm")
    edap.delete_org_unit("lm")
    assert not edap.subobject_exists_at("ou=lm", "organizationalUnit", )


def test_cz_res_lm_becomes_present(edap):
    description = b'CZ-Research'
    assert not edap.object_exists_at(f"cn=cz-res,{edap.LM_GROUP}", "posixGroup")
    edap.create_lm("cz-res", display_name="CZ-Research")
    assert edap.object_exists_at(f"cn=cz-res,{edap.LM_GROUP}", "posixGroup")
    res = edap.get_lm("cz-res")
    assert description in res['description']


def test_get_objects(edap):
    """ Test LdapObjectsMixin's get_objects, get_object methods """
    org_unit = "testObjects"
    assert len(edap.get_objects(search=f"ou={org_unit}", obj_class="organizationalUnit")) == 0
    edap.create_org_unit(f"{org_unit}")
    assert edap.get_objects(relative_pos=f"ou={org_unit}") == edap.get_objects(relative_pos=f"ou={org_unit}")
    assert len(edap.get_subobjects(relative_pos=f"ou={org_unit}", obj_class="organizationalUnit")) == 1
    assert not edap.get_subobjects(f"ou={org_unit}", search="cname=foobar")
    edap.delete_org_unit(f"{org_unit}")


def test_delete_object(edap):
    """ Test LdapObjectsMixin's delete_object method """
    group_name = 'toDelete'
    group_ou_name = 'toDeleteDivision'
    new_object_dn = f"cn={group_name},ou={group_ou_name},{edap.BASE_DN}"
    edap.create_group(name=group_name, organizational_unit=group_ou_name)
    assert len(edap.search_s(new_object_dn, ldap.SCOPE_BASE))
    edap.delete_object(new_object_dn)
    with pytest.raises(ldap.NO_SUCH_OBJECT):
        len(edap.search_s(new_object_dn, ldap.SCOPE_BASE))


def test_delete_group(edap):
    group_cname = 'groupToDelete'
    group_ou = 'ouToDelete'
    edap.create_group(group_cname, group_ou)
    assert edap.get_group(group_cname, group_ou)
    edap.delete_group(group_cname, group_ou)
    with pytest.raises(ObjectDoesNotExist):
        edap.get_group(group_cname, group_ou)


def test_delete_user(edap):
    uid = 'userToDelete'
    edap.ensure_org_unit_exists("people")
    edap.add_user(uid, 'test_name', 'test_surname', 'testpassword', "foo@bar.com")
    assert edap.get_user(uid)
    edap.delete_user(uid)
    with pytest.raises(ObjectDoesNotExist):
        edap.get_user(uid)


def test_delete_division(edap):
    division_cname = 'divisionToDelete'
    edap.create_division(division_cname)
    assert edap.get_division(division_cname)
    edap.delete_division(division_cname)
    with pytest.raises(ObjectDoesNotExist):
        edap.get_division(division_cname)


def test_get_users(edap):
    """ Test LdapUserMixin's get_users, get_user methods """
    user_id = 'testUser'
    assert len(edap.get_users(search=f"uid={user_id}")) == 0
    edap.ensure_org_unit_exists("people")
    edap.add_user(user_id, 'test', 'test', 'testPassword', "foo@bar.com")

    assert not edap.verify_user_password(user_id, "lalala")
    assert edap.verify_user_password(user_id, "testPassword")
    edap.modify_user(user_id, dict(userPassword="lalala"))
    assert not edap.verify_user_password(user_id, "testPassword")
    assert edap.verify_user_password(user_id, "lalala")

    assert edap.get_user(user_id)["mail"][0] == b"foo@bar.com"
    edap.modify_user(user_id, dict(mail="foo@bar.baz"))
    assert edap.get_user(user_id)["mail"][0] == b"foo@bar.baz"
    assert len(edap.get_users(search=f"uid={user_id}")) == 1
    assert edap.get_user(user_id) == edap.get_users(search=f"uid={user_id}")[0]


def test_get_user_groups(edap):
    """ Test LdapUserMixin's get_user_groups method """
    user_id = 'testUserGroups'
    group_name = 'test_user_groups'
    edap.ensure_org_unit_exists("people")
    edap.add_user(user_id, 'test', 'test', 'testPassword', "foo@bar.com")
    edap.create_division(group_name)
    assert len(edap.get_user_groups(user_id)) == 0
    edap.make_uid_member_of(user_id, f'cn={group_name},{edap.DIVISIONS_GROUP}')
    assert len(edap.get_user_groups(user_id)) == 1
    assert edap.get_user_groups(user_id)[0]['cn'][0] == group_name.encode('utf-8')


def test_user_becomes_present(edap):
    assert not edap.user_of_uid_exists("kohout")
    edap.add_user("kohout", "Kohutik", "Pestry", "kohuticek", "foo@bar.com")
    assert edap.user_of_uid_exists("kohout")


def test_it_division_becomes_present(edap):
    description = b"It division"
    assert not edap.object_exists_at(f"cn=it,{edap.DIVISIONS_GROUP}", "posixGroup")
    edap.create_division("it", display_name=description)
    assert edap.object_exists_at(f"cn=it,{edap.DIVISIONS_GROUP}", "posixGroup")
    res = edap.get_division("it")
    assert description in res['description']


def test_new_it_guy(edap):
    IT_GROUP_DN = f"cn=it,{edap.DIVISIONS_GROUP}"
    DDEA_IT_GROUP_DN = f"cn=it,{edap.DDEA_GROUP}"

    assert not edap.uid_is_member_of_group(IT_GROUP_DN, "kohout")

    edap.make_uid_member_of("kohout", IT_GROUP_DN)
    assert edap.uid_is_member_of_group(IT_GROUP_DN, "kohout")
    edap.remove_uid_member_of("kohout", IT_GROUP_DN)
    assert not edap.uid_is_member_of_group(IT_GROUP_DN, "kohout")

    edap.make_uid_member_of_division("kohout", "it")
    assert edap.uid_is_member_of_group(IT_GROUP_DN, "kohout")

    assert not edap.uid_is_member_of_group(DDEA_IT_GROUP_DN, "kohout")
    edap.make_uid_member_of_ddea("kohout", "it")
    assert edap.uid_is_member_of_group(DDEA_IT_GROUP_DN, "kohout")
    edap.remove_uid_member_of_ddea("kohout", "it")
    assert not edap.uid_is_member_of_group(DDEA_IT_GROUP_DN, "kohout")

    edap.remove_uid_member_of_division("kohout", "it")
    assert not edap.uid_is_member_of_group(IT_GROUP_DN, "kohout")
    # No error should occur
    edap.remove_uid_member_of_division("kohout", "it")

    with pytest.raises(ConstraintError):
        edap.make_uid_member_of_division("kohout", "ill")

    with pytest.raises(ConstraintError):
        edap.make_uid_member_of("blbec", IT_GROUP_DN)


def test_label_franchise(edap):
    assert edap.label_franchise("cz") == "Czechia"
    assert edap.label_franchise("cz_prg") == "Czechia"
    double_underscore_code = 'cz__'
    with pytest.raises(KeyError):
        assert edap.label_franchise(double_underscore_code)
    invalid_code = 'cz_'
    with pytest.raises(KeyError):
        assert edap.label_franchise(invalid_code)


def test_czech_franchise_becomes_present(edap):
    franchise_cname = 'cz_prg'
    franchise_description = 'Czechia'
    assert not edap.subobject_exists_at(f"cn={franchise_cname},{edap.FRANCHISES_OU}", "posixGroup")
    edap.create_franchise(franchise_cname)
    assert edap.subobject_exists_at(f"cn={franchise_cname},{edap.FRANCHISES_OU}", "posixGroup")
    assert edap.object_exists(f"&(commonName={franchise_cname})(description={franchise_description})", "posixGroup")
    assert edap.get_franchise(franchise_cname)['cn'][0] == franchise_cname.encode('utf-8')
    assert edap.get_franchise(franchise_cname)['description'][0] == franchise_description.encode('utf-8')


def test_create_franchise_custom_name(edap):
    franchise_cname = 'ua'
    franchise_description = 'Franchise custom name'
    with pytest.raises(ObjectDoesNotExist):
        edap.get_franchise(franchise_cname)
    edap.create_franchise(franchise_cname, franchise_description)
    franchise = edap.get_franchise(franchise_cname)
    assert franchise['description'][0] == franchise_description.encode('utf-8')

    edap.delete_franchise(franchise_cname)


def test_corresponding_teams(edap):
    """ test func to ensure that all existing teams correspond to countries and divisions """
    us_franchise_code = 'us'
    us_franchise_display_name = edap.label_franchise(us_franchise_code)
    edap.create_franchise(us_franchise_code)

    test_division_cn = 'test-div'
    test_division_display_name = 'test division'
    edap.create_division(test_division_cn, test_division_display_name)

    team_display_name = edap.make_team_display_name(us_franchise_display_name, test_division_display_name)
    team_machine_name = edap.make_team_machine_name(us_franchise_code, test_division_cn)
    edap.create_team(team_machine_name, team_display_name)
    # assert all teams are valid
    assert len(get_not_matching_teams_by_cn(edap)) == 0

    # add team with not existing division
    wrong_division_team_cn = "{}-{}".format(us_franchise_code, 'not-existing-division')
    edap.create_team(wrong_division_team_cn, 'test team')
    not_corresponding_teams = get_not_matching_teams_by_cn(edap)
    assert len(not_corresponding_teams) == 1
    assert not_corresponding_teams[0]['cn'][0].decode('utf-8') == wrong_division_team_cn

    # add team with not existing franchise
    wrong_franchise_team_cn = "not-existing-franchise-{}".format(test_division_cn)
    edap.create_team(wrong_franchise_team_cn, 'test team')
    not_corresponding_teams = get_not_matching_teams_by_cn(edap)
    not_corresponding_teams_cns = [each['cn'][0].decode('utf-8') for each in not_corresponding_teams]
    assert len(not_corresponding_teams) == 2
    assert wrong_franchise_team_cn in not_corresponding_teams_cns
    assert wrong_division_team_cn in not_corresponding_teams_cns

    edap.delete_team(wrong_division_team_cn)
    edap.delete_team(wrong_franchise_team_cn)


def test_corresponding_teams_by_description(edap):
    """ test func to ensure that all existing teams correspond to countries and divisions """
    ua_franchise_code = 'ua'
    ua_franchise_display_name = edap.label_franchise(ua_franchise_code)
    edap.create_franchise(ua_franchise_code)

    test_division_cn = 'test-div-2'
    test_division_display_name = 'test division'
    edap.create_division(test_division_cn, test_division_display_name)

    team_display_name = edap.make_team_display_name(ua_franchise_display_name, test_division_display_name)
    team_machine_name = edap.make_team_machine_name(ua_franchise_code, test_division_cn)
    edap.create_team(team_machine_name, team_display_name)
    # assert all teams are valid
    assert len(get_not_matching_teams_by_description(edap)) == 0
    edap.delete_team(team_machine_name)

    # add team with invalid description
    team_display_name = edap.make_team_display_name(ua_franchise_display_name, test_division_display_name) + ' invalid'
    team_machine_name = edap.make_team_machine_name(ua_franchise_code, test_division_cn)
    edap.create_team(team_machine_name, team_display_name)
    assert len(get_not_matching_teams_by_description(edap)) == 1
    assert get_not_matching_teams_by_description(edap)[0]['description'][0].decode('utf-8') == team_display_name
    edap.delete_team(team_machine_name)

    # add team with reverse description name
    team_display_name = "{} {}".format(test_division_display_name, ua_franchise_display_name)
    team_machine_name = edap.make_team_machine_name(ua_franchise_code, test_division_cn)
    edap.create_team(team_machine_name, team_display_name)
    assert len(get_not_matching_teams_by_description(edap)) == 1
    assert get_not_matching_teams_by_description(edap)[0]['description'][0].decode('utf-8') == team_display_name


def test_get_single_object():
    """ test get_single_object func """
    data_empty = []
    data_single = [('cn=test,dc=entint,dc=org', {'cn': 'test'})]
    data_multiple = [('cn=test,dc=entint,dc=org', {'cn': 'test'}), ('cn=test,dc=entint,dc=org', {'cn': 'test'})]
    with pytest.raises(ObjectDoesNotExist):
        get_single_object(data_empty)
    with pytest.raises(MultipleObjectsFound):
        get_single_object(data_multiple)

    assert data_single[0] == get_single_object(data_single)
