import hashlib
import os
import codecs
import argparse

import ldap
import ldap.modlist

import constants as c


class ConstraintError(RuntimeError):
    pass


def _hashPassword(password):
    salt = os.urandom(4)
    h = hashlib.sha1(password.encode("ASCII"))
    h.update(salt)
    hashed = "{SSHA}".encode() + codecs.encode(h.digest() + salt, "base64").strip()
    return hashed


def mk_add_user_modlist(uid, name, surname, password):
    mail = f"{uid}@example.com".encode("ASCII")
    dic = dict(
         uid=uid.encode("ASCII"), givenName=name.encode("UTF-8"),
         mail=mail, objectclass=(b"inetOrgPerson", b"top"),
         sn=surname.encode("UTF-8"), userPassword=_hashPassword(password),
         cn=f"{name} {surname}".encode("UTF-8"),
    )
    modlist = ldap.modlist.addModlist(dic)
    return modlist


def object_exists(bound_ldap, search, obj_class=None):
    if obj_class is not None:
        search = f"&({search})(objectClass={obj_class})"
    found = bound_ldap.search_s(bound_ldap.BASE_DN, ldap.SCOPE_SUBTREE, f"({search})")
    return len(found)


def subobject_exists_at(bound_ldap, relative_pos, obj_class, additional_search=None):
    root = f"{relative_pos},{bound_ldap.BASE_DN}"
    return object_exists_at(bound_ldap, root, obj_class, additional_search)


def object_exists_at(bound_ldap, root, obj_class, additional_search=None):
    search = f"objectClass={obj_class}"
    if additional_search is not None:
        search = f"&({search})({additional_search})"
    try:
        found = bound_ldap.search_s(root, ldap.SCOPE_BASE, f"({search})")
    except Exception:
        return 0
    return len(found)


def create_org_unit(bound_ldap, name, fqdn):
    dic = dict(
         ou=name.encode("ASCII"),
         objectclass=(b"organizationalUnit", b"top"),
    )
    modlist = ldap.modlist.addModlist(dic)
    bound_ldap.add_s(fqdn, modlist)


def uid_is_member_of_group(bound_ldap, group_fqdn, uid):
    search = f"memberUid={uid}"
    found = bound_ldap.search_s(group_fqdn, ldap.SCOPE_BASE, f"({search})")
    return len(found)


def create_group_dict(name):
    dic = dict(
        cn=name.encode("ASCII"), objectclass=(b"posixGroup", b"top"), gidNumber=b"500",
    )
    return dic


def create_group_from_dict(bound_ldap, fqdn, dic):
    modlist = ldap.modlist.addModlist(dic)
    bound_ldap.add_s(fqdn, modlist)


def add_user(bound_ldap, uid, name, surname, password):
    if subobject_exists_at(bound_ldap, "ou=people", "organizationalUnit") == 0:
        raise ConstraintError(f"The people group '{bound_ldap.PEOPLE_GROUP}' doesn't exist.")
    if user_of_uid_exists(bound_ldap, uid) > 0:
        raise ConstraintError(f"User of uid '{uid}' already exists.")
    modlist = mk_add_user_modlist(uid, name, surname, password)
    bound_ldap.add_s(f"uid={uid},{bound_ldap.PEOPLE_GROUP}", modlist)


def user_of_uid_exists(bound_ldap, uid):
    if subobject_exists_at(bound_ldap, "ou=people", "organizationalUnit") == 0:
        raise ConstraintError(f"The people group '{bound_ldap.PEOPLE_GROUP}' doesn't exist.")
    found = bound_ldap.search_s(f"{bound_ldap.PEOPLE_GROUP}", ldap.SCOPE_ONELEVEL, f"(uid={uid})")
    return len(found)


def create_division(bound_ldap, name):
    if not subobject_exists_at(bound_ldap, bound_ldap.DIVISIONS, "organizationalUnit"):
        create_org_unit(bound_ldap, bound_ldap.DIVISIONS, bound_ldap.DIVISIONS_GROUP)
    if not subobject_exists_at(bound_ldap, f"cn={name},{bound_ldap.DIVISIONS}", "posixGroup"):
        dic = create_group_dict(f"{name}")
        create_group_from_dict(bound_ldap, f"cn={name},{bound_ldap.DIVISIONS_GROUP}", dic)


def create_service_group(bound_ldap, name):
    if not subobject_exists_at(bound_ldap, bound_ldap.SERVICES, "organizationalUnit"):
        create_org_unit(bound_ldap, bound_ldap.SERVICES, bound_ldap.SERVICES_GROUP)
    if not subobject_exists_at(bound_ldap, f"cn={name},{bound_ldap.SERVICES}", "posixGroup"):
        dic = create_group_dict(f"{name}")
        create_group_from_dict(bound_ldap, f"cn={name},{bound_ldap.SERVICES_GROUP}", dic)


def make_uid_member_of(bound_ldap, uid, group_fqdn):
    if object_exists_at(bound_ldap, group_fqdn, "posixGroup") == 0:
        raise ConstraintError(f"Group {group_fqdn} doesn't exist.")
    if user_of_uid_exists(bound_ldap, uid) == 0:
        msg = f"User of uid '{uid}' doesn't exist, so we can't add it to any group."
        raise ConstraintError(msg)
    if uid_is_member_of_group(bound_ldap, group_fqdn, uid):
        return
    modlist = [(ldap.MOD_ADD, "memberUid", [uid.encode("ASCII")])]
    bound_ldap.modify_s(group_fqdn, modlist)


def make_uid_member_of_division(bound_ldap, uid, name):
    group_fqdn = f"cn={name},{bound_ldap.DIVISIONS_GROUP}"
    return make_uid_member_of(bound_ldap, uid, group_fqdn)


def make_uid_member_of_service_group(bound_ldap, uid, name):
    group_fqdn = f"cn={name},{bound_ldap.SERVICES_GROUP}"
    return make_uid_member_of(bound_ldap, uid, group_fqdn)


def remove_uid_member_of(bound_ldap, uid, group_fqdn):
    if object_exists_at(bound_ldap, group_fqdn, "posixGroup") == 0:
        raise ConstraintError(f"Group {group_fqdn} doesn't exist.")
    if not uid_is_member_of_group(bound_ldap, group_fqdn, uid):
        return
    if user_of_uid_exists(bound_ldap, uid) == 0:
        msg = f"User of uid '{uid}' doesn't exist, so we can't add it to any group."
        raise ConstraintError(msg)
    modlist = [(ldap.MOD_DELETE, "memberUid", [uid.encode("ASCII")])]
    bound_ldap.modify_s(group_fqdn, modlist)


def remove_uid_member_of_division(bound_ldap, uid, name):
    group_fqdn = f"cn={name},{bound_ldap.DIVISIONS_GROUP}"
    return remove_uid_member_of(bound_ldap, uid, group_fqdn)


def remove_uid_member_of_service_group(bound_ldap, uid, name):
    group_fqdn = f"cn={name},{bound_ldap.SERVICES_GROUP}"
    return remove_uid_member_of(bound_ldap, uid, group_fqdn)


def create_franchise(bound_ldap, name):
    if not subobject_exists_at(bound_ldap, bound_ldap.FRANCHISES, "organizationalUnit"):
        create_org_unit(bound_ldap, bound_ldap.FRANCHISES, bound_ldap.FRANCHISES_GROUP)
    if not subobject_exists_at(bound_ldap, f"cn={name},{bound_ldap.FRANCHISES}", "posixGroup"):
        dic = create_group_dict(f"{name}")
        dic["description"] = label_franchise(name).encode("UTF-8")
        create_group_from_dict(bound_ldap, f"cn={name},{bound_ldap.FRANCHISES_GROUP}", dic)


def label_franchise(name):
    for code, country_name in c.COUNTRIES_CODES.items():
        if name.startswith(code):
            return country_name
    raise KeyError(f"Invalid country code to match '{name}'")


def create_all_divisions(bound_ldap, source):
    for dname in source:
        create_division(bound_ldap, dname)


def create_all_franchises(bound_ldap, source):
    for frname in source:
        create_franchise(bound_ldap, frname)


def ensure_org_sanity(bound_ldap, source):
    create_all_divisions(bound_ldap, source["divisions"])
    create_all_franchises(bound_ldap, source["countries"])
    create_org_unit(bound_ldap, "people", bound_ldap.PEOPLE_GROUP)
    create_org_unit(bound_ldap, "people", bound_ldap.PEOPLE_GROUP)


class BoundLdap(object):
    def __init__(self, hostname, admin_cn, password, domain=None):

        if domain is None:
            domain = "example.com"
        domain_components = domain.split(".")
        basedn_components = [f"dc={c}" for c in domain_components]
        self.BASE_DN = ",".join(basedn_components)

        admin_dn = f"{admin_cn},{self.BASE_DN}"
        self.ldap = ldap.initialize("ldap://{}".format(hostname))
        self.ldap.bind_s(admin_dn, password)

        self.PEOPLE_GROUP = f"ou=people,{self.BASE_DN}"
        self.DIVISIONS = "ou=divisions"
        self.DIVISIONS_GROUP = f"{self.DIVISIONS},{self.BASE_DN}"
        self.FRANCHISES = "ou=franchises"
        self.FRANCHISES_GROUP = f"{self.FRANCHISES},{self.BASE_DN}"
        self.SERVICES = "ou=services"
        self.SERVICES_GROUP = f"{self.SERVICES},{self.BASE_DN}"

    def add_s(self, * args, ** kwargs):
        return self.ldap.add_s(* args, ** kwargs)

    def modify_s(self, * args, ** kwargs):
        return self.ldap.modify_s(* args, ** kwargs)

    def search_s(self, * args, ** kwargs):
        return self.ldap.search_s(* args, ** kwargs)


def update_parser(parser=None):
    if parser is None:
        parser = argparse.ArgumentParser()
    parser.add_argument("hostname")
    parser.add_argument("--password", "-p")
    parser.add_argument("--admin-dn", "-u")
    return parser


if __name__ == "__main__":
    parser = update_parser()
    args = parser.parse_args()

    ld = BoundLdap(args.hostname, args.admin_dn, args.password)
