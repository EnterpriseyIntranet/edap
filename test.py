import os
import collections

import pytest

from edap import Edap, ConstraintError
import import_data

DOMAIN = os.environ.get("DOMAIN")
ADMIN_CN = "cn=admin"
ADMIN_PASSWORD = os.environ.get("LDAP_ADMIN_PASSWORD")


@pytest.fixture(scope="session")
def edap():
    edap = Edap("ldap", ADMIN_CN, ADMIN_PASSWORD, DOMAIN)
    print(ADMIN_CN, ADMIN_PASSWORD)
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


def test_blank(edap):
    assert not edap.subobject_exists_at(f"ou=people", "organizationalUnit")
    edap.create_org_unit("people", edap.PEOPLE_GROUP)
    assert edap.subobject_exists_at("ou=people", "organizationalUnit",)
    assert not edap.subobject_exists_at("ou=people", "foobar")


def test_user_becomes_present(edap):
    assert not edap.user_of_uid_exists("kohout")
    edap.add_user("kohout", "Kohutik", "Pestry", "kohuticek")
    assert edap.user_of_uid_exists("kohout")


def test_divisions_becomes_present(edap):
    assert not edap.org_unit_exists("divisions")
    edap.create_org_unit("ou=divisions", edap.DIVISIONS_GROUP)
    assert edap.org_unit_exists("divisions")


def test_it_division_becomes_present(edap):
    assert not edap.object_exists_at(f"cn=it,{edap.DIVISIONS_GROUP}", "posixGroup")
    edap.create_division("it")
    assert edap.object_exists_at(f"cn=it,{edap.DIVISIONS_GROUP}", "posixGroup")


def test_new_it_guy(edap):
    it_group_dn = f"cn=it,{edap.DIVISIONS_GROUP}"
    assert not edap.uid_is_member_of_group(it_group_dn, "kohout")

    edap.make_uid_member_of("kohout", it_group_dn)
    assert edap.uid_is_member_of_group(it_group_dn, "kohout")
    edap.remove_uid_member_of("kohout", it_group_dn)
    assert not edap.uid_is_member_of_group(it_group_dn, "kohout")

    edap.make_uid_member_of_division("kohout", "it")
    assert edap.uid_is_member_of_group(it_group_dn, "kohout")
    edap.remove_uid_member_of_division("kohout", "it")
    assert not edap.uid_is_member_of_group(it_group_dn, "kohout")
    # No error should occur
    edap.remove_uid_member_of_division("kohout", "it")

    with pytest.raises(ConstraintError):
        edap.make_uid_member_of_division("kohout", "ill")

    with pytest.raises(ConstraintError):
        edap.make_uid_member_of("blbec", it_group_dn)


def test_czech_franchise_becomes_present(edap):
    assert not edap.subobject_exists_at(f"cn=cz_prg,{edap.FRANCHISES}", "posixGroup")
    edap.create_franchise("cz_prg")
    assert edap.subobject_exists_at(f"cn=cz_prg,{edap.FRANCHISES}", "posixGroup")
    assert edap.object_exists(f"&(commonName=cz_prg)(description=Czech Republic)", "posixGroup")


def test_label_franchise(edap):
    assert edap.label_franchise("cz") == "Czech Republic"
    assert edap.label_franchise("cz_prg") == "Czech Republic"
    with pytest.raises(KeyError):
        assert edap.label_franchise("@@")
