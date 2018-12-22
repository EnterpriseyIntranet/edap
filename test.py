import os
import collections

import pytest

import edap
import import_data

DOMAIN = os.environ.get("DOMAIN")
ADMIN_CN = "cn=admin"
ADMIN_PASSWORD = os.environ.get("LDAP_ADMIN_PASSWORD")


@pytest.fixture(scope="session")
def ldap():
    ldap = edap.BoundLdap("ldap", ADMIN_CN, ADMIN_PASSWORD, DOMAIN)
    print(ADMIN_CN, ADMIN_PASSWORD)
    yield ldap
    ldap.ldap.unbind_s()


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


def test_blank(ldap):
    assert not edap.subobject_exists_at(ldap, f"ou=people", "organizationalUnit")
    edap.create_org_unit(ldap, "people", ldap.PEOPLE_GROUP)
    assert edap.subobject_exists_at(ldap, "ou=people", "organizationalUnit",)
    assert not edap.subobject_exists_at(ldap, "ou=people", "foobar")


def test_user_becomes_present(ldap):
    assert not edap.user_of_uid_exists(ldap, "kohout")
    edap.add_user(ldap, "kohout", "Kohutik", "Pestry", "kohuticek")
    assert edap.user_of_uid_exists(ldap, "kohout")


def test_divisions_becomes_present(ldap):
    assert not edap.subobject_exists_at(ldap, "ou=divisions", "organizationalUnit")
    edap.create_org_unit(ldap, "ou=divisions", ldap.DIVISIONS_GROUP)
    assert edap.subobject_exists_at(ldap, "ou=divisions", "organizationalUnit")


def test_it_division_becomes_present(ldap):
    assert not edap.object_exists_at(ldap, f"cn=it,{ldap.DIVISIONS_GROUP}", "posixGroup")
    edap.create_division(ldap, "it")
    assert edap.object_exists_at(ldap, f"cn=it,{ldap.DIVISIONS_GROUP}", "posixGroup")


def test_new_it_guy(ldap):
    it_group_dn = f"cn=it,{ldap.DIVISIONS_GROUP}"
    assert not edap.uid_is_member_of_group(ldap, it_group_dn, "kohout")

    edap.make_uid_member_of(ldap, "kohout", it_group_dn)
    assert edap.uid_is_member_of_group(ldap, it_group_dn, "kohout")
    edap.remove_uid_member_of(ldap, "kohout", it_group_dn)
    assert not edap.uid_is_member_of_group(ldap, it_group_dn, "kohout")

    edap.make_uid_member_of_division(ldap, "kohout", "it")
    assert edap.uid_is_member_of_group(ldap, it_group_dn, "kohout")
    edap.remove_uid_member_of_division(ldap, "kohout", "it")
    assert not edap.uid_is_member_of_group(ldap, it_group_dn, "kohout")
    # No error should occur
    edap.remove_uid_member_of_division(ldap, "kohout", "it")

    with pytest.raises(edap.ConstraintError):
        edap.make_uid_member_of_division(ldap, "kohout", "ill")

    with pytest.raises(edap.ConstraintError):
        edap.make_uid_member_of(ldap, "blbec", it_group_dn)


def test_czech_franchise_becomes_present(ldap):
    assert not edap.subobject_exists_at(ldap, f"cn=cz_prg,{ldap.FRANCHISES}", "posixGroup")
    edap.create_franchise(ldap, "cz_prg")
    assert edap.subobject_exists_at(ldap, f"cn=cz_prg,{ldap.FRANCHISES}", "posixGroup")
    assert edap.object_exists(ldap, f"&(commonName=cz_prg)(description=Czech Republic)", "posixGroup")


def test_label_franchise():
    assert edap.label_franchise("cz") == "Czech Republic"
    assert edap.label_franchise("cz_prg") == "Czech Republic"
    with pytest.raises(KeyError):
        assert edap.label_franchise("@@")
