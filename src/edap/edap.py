import hashlib
import os
import codecs
import argparse

import ldap
import ldap.modlist

from edap import constants as c


def get_str(str_or_bytes):
    """
    Decode argument to unicode, utf-8 if it is bytestring, just return otherwise
    Args:
        str_or_bytes (str/bytes): arg to decode or return

    Returns (str):
    """
    return str_or_bytes.decode('utf-8') if isinstance(str_or_bytes, bytes) else str_or_bytes


def transform_ldap_response(ldap_response):
    """
    Transform list of ldap tuples to list of dicts
    Args:
        ldap_response (list):

    Returns:
    """
    return [ldap_tuple_to_object(each) for each in ldap_response]


def ldap_tuple_to_object(ldap_tuple):
    """
    Transform tuple from ldap response (dn, attributes) to dict with all attributes and dn as fqdn

    Args:
        ldap_tuple (tuple): object from ldap response

    Returns:
    """
    return {
        'fqdn': ldap_tuple[0],
        **ldap_tuple[1]
    }


class ConstraintError(RuntimeError):
    pass


class ObjectDoesNotExist(Exception):
    """ Base exception if searched object cannot be found """
    pass


class MultipleObjectsFound(Exception):
    """ Base exception if found more than one object """
    pass


def get_single_object(data):
    """ Get first element of a list, or raise Exception if list length > 1 or equals 0 """
    if len(data) == 0:
        raise ObjectDoesNotExist('Object does not exist')
    elif len(data) > 1:
        raise MultipleObjectsFound('Multiple objects found')
    return data[0]


def _hashPassword(password):
    salt = os.urandom(4)
    h = hashlib.sha1(password.encode("ASCII"))
    h.update(salt)
    hashed = "{SSHA}".encode() + codecs.encode(h.digest() + salt, "base64").strip()
    return hashed


class LdapObjectsMixin(object):

    def object_exists(self, search, obj_class=None):
        if obj_class is not None:
            search = f"&({search})(objectClass={obj_class})"
        found = self.search_s(self.BASE_DN, ldap.SCOPE_SUBTREE, f"({search})")
        return len(found)

    def object_exists_at(self, root, obj_class, additional_search=None):
        search = f"objectClass={obj_class}"
        if additional_search is not None:
            search = f"&({search})({additional_search})"
        try:
            found = self.search_s(root, ldap.SCOPE_BASE, f"({search})")
        except Exception:
            return 0
        return len(found)

    def subobject_exists_at(self, relative_pos, obj_class, additional_search=None):
        root = f"{relative_pos},{self.BASE_DN}"
        return self.object_exists_at(root, obj_class, additional_search)

    def get_objects(self, search=None, relative_pos=None, obj_class=None):
        root = self.BASE_DN
        if obj_class is not None:
            if search:
                search = f"(&({search})(objectClass={obj_class}))"
            else:
                search = f"(objectClass={obj_class})"
        if relative_pos:
            root = f"{relative_pos},{root}"
        return transform_ldap_response(self.search_s(root, ldap.SCOPE_SUBTREE, search))

    def get_subobjects(self, relative_pos, search=None, obj_class=None):
        return self.get_objects(search=search, relative_pos=relative_pos, obj_class=obj_class)

    def delete_object(self, dn):
        """ Delete object by dn """
        return self.delete_s(dn)


class LdapUserMixin(object):

    def add_user(self, uid, name, surname, password, mail, picture_bytes=b""):
        if self.subobject_exists_at("ou=people", "organizationalUnit") == 0:
            raise ConstraintError(f"The people group '{self.PEOPLE_GROUP}' doesn't exist.")
        if self.user_of_uid_exists(uid) > 0:
            raise ConstraintError(f"User of uid '{uid}' already exists.")
        modlist = self._mk_add_user_modlist(uid, name, surname, password, mail, picture_bytes)
        self.add_s(f"uid={uid},{self.PEOPLE_GROUP}", modlist)

    def get_users(self, search=None):
        """
        Get subobjects of organizational unit "people"

        Args:
            search (str): search filter

        Returns:
        """
        return self.get_subobjects('ou=people', search, obj_class='inetOrgPerson')

    def get_user(self, uid):
        """
        Search in subobjects of organizational unit "people" by uid
        Args:
            uid (str):

        Returns:
        """
        return get_single_object(self.get_users(search=f"uid={uid}"))

    def get_user_groups(self, uid):
        """
        Get groups where user is a member

        Args:
            uid (str): user id

        Returns (list):
        """
        search = f"(&(memberUid={uid})(objectClass=posixGroup))"
        return transform_ldap_response(self.search_s(self.BASE_DN, ldap.SCOPE_SUBTREE, search))

    def _mk_add_user_dict(self, uid, name, surname, password, mail, picture_bytes):
        mail = mail.encode("ASCII")
        dic = dict(
            uid=uid.encode("ASCII"), givenName=name.encode("UTF-8"),
            mail=mail, objectClass=(b"inetOrgPerson", b"top"),
            sn=surname.encode("UTF-8"), userPassword=_hashPassword(password),
            cn=f"{name} {surname}".encode("UTF-8"),
            jpegPhoto=picture_bytes,
        )
        return dic

    def _mk_add_user_modlist(self, uid, name, surname, password, mail, picture_bytes):
        dic = self._mk_add_user_dict(uid, name, surname, password, mail, picture_bytes)
        modlist = ldap.modlist.addModlist(dic)
        return modlist

    def user_of_uid_exists(self, uid):
        if self.subobject_exists_at("ou=people", "organizationalUnit") == 0:
            raise ConstraintError(f"The people group '{self.PEOPLE_GROUP}' doesn't exist.")
        found = self.search_s(f"{self.PEOPLE_GROUP}", ldap.SCOPE_ONELEVEL, f"(uid={uid})")
        return len(found)

    def uid_is_member_of_group(self, group_fqdn, uid):
        search = f"memberUid={uid}"
        found = self.search_s(group_fqdn, ldap.SCOPE_BASE, f"({search})")
        return len(found)

    def make_uid_member_of(self, uid, group_fqdn):
        if self.object_exists_at(group_fqdn, "posixGroup") == 0:
            raise ConstraintError(f"Group {group_fqdn} doesn't exist.")
        if self.user_of_uid_exists(uid) == 0:
            msg = f"User of uid '{uid}' doesn't exist, so we can't add it to any group."
            raise ConstraintError(msg)
        if self.uid_is_member_of_group(group_fqdn, uid):
            return
        modlist = [(ldap.MOD_ADD, "memberUid", [uid.encode("ASCII")])]
        self.modify_s(group_fqdn, modlist)

    def make_uid_member_of_division(self, uid, name):
        group_fqdn = f"cn={name},{self.DIVISIONS_GROUP}"
        return self.make_uid_member_of(uid, group_fqdn)

    def make_uid_member_of_service_group(self, uid, name):
        group_fqdn = f"cn={name},{self.SERVICES_GROUP}"
        return self.make_uid_member_of(uid, group_fqdn)

    def make_user_member_of_franchise(self, uid, franchise_name):
        """
        Make user member of franchise group
        Args:
            uid (str): user uid
            franchise_name (str): cname of a franchise

        Returns:
        """
        group_fqdn = f"cn={franchise_name},{self.FRANCHISES_GROUP}"
        return self.make_uid_member_of(uid, group_fqdn)

    def make_user_member_of_team(self, uid, team_machine_name):
        """
        Make user member of team group

        Args:
            uid (str): user uid
            team_machine_name (str): cn of a team

        Returns:
        """
        group_fqdn = f"cn={team_machine_name},{self.TEAMS_GROUP}"
        return self.make_uid_member_of(uid, group_fqdn)

    def remove_uid_member_of(self, uid, group_fqdn):
        if self.object_exists_at(group_fqdn, "posixGroup") == 0:
            raise ConstraintError(f"Group {group_fqdn} doesn't exist.")
        if not self.uid_is_member_of_group(group_fqdn, uid):
            return
        if self.user_of_uid_exists(uid) == 0:
            msg = f"User of uid '{uid}' doesn't exist, so we can't add it to any group."
            raise ConstraintError(msg)
        modlist = [(ldap.MOD_DELETE, "memberUid", [uid.encode("ASCII")])]
        self.modify_s(group_fqdn, modlist)

    def remove_uid_member_of_division(self, uid, name):
        group_fqdn = f"cn={name},{self.DIVISIONS_GROUP}"
        return self.remove_uid_member_of(uid, group_fqdn)

    def remove_uid_member_of_service_group(self, uid, name):
        group_fqdn = f"cn={name},{self.SERVICES_GROUP}"
        return self.remove_uid_member_of(uid, group_fqdn)

    def remove_uid_member_of_franchise(self, uid, franchise_name):
        group_fqdn = f"cn={franchise_name},{self.FRANCHISES_GROUP}"
        return self.remove_uid_member_of(uid, group_fqdn)

    def remove_uid_member_of_team(self, uid, team_name):
        group_fqdn = f"cn={team_name},{self.TEAMS_GROUP}"
        return self.remove_uid_member_of(uid, group_fqdn)

    def delete_user(self, uid):
        return self.delete_object(f"uid={uid},{self.PEOPLE_GROUP}")


class LdapPostfixUserMixin(LdapUserMixin):
    MAIL_GID = 5000
    MAIL_UID = 5000
    HOME_FORMAT_STR = "/var/mail/mail.cspii.org/{uid}"

    def _mk_add_user_dict(self, uid, name, surname, password, mail, picture_bytes):
        dic = super()._mk_add_user_dict(uid, name, surname, password, mail, picture_bytes)
        postfix_dic = dict(
            mailEnabled=b"TRUE",
            mailGidNumber=str(self.MAIL_GID).encode("ASCII"),
            mailUidNumber=str(self.MAIL_UID).encode("ASCII"),
            mailHomeDirectory=self.HOME_FORMAT_STR.format(
                uid=uid, name=name, surname=surname, mail=mail).encode("ASCII"),
        )
        dic.update(postfix_dic)
        dic["objectClass"] += (b"postfixBookMailAccount",)
        return dic


class OrganizationalUnitMixin(object):

    def create_org_unit(self, name, base=None):
        if base is None:
            base = self.BASE_DN

        dn = f"ou={name}"
        fqdn = f"{dn},{base}"

        dic = dict(
            ou=dn.encode("ASCII"),
            objectClass=(b"organizationalUnit", b"top"),
        )
        modlist = ldap.modlist.addModlist(dic)
        self.add_s(fqdn, modlist)

    def delete_org_unit(self, name, base=None):
        if base is None:
            base = self.BASE_DN

        self.delete_object(f"ou={name},{base}")

    def ensure_org_unit_exists(self, name, base=None):
        if base is None:
            base = self.BASE_DN

        if not self.org_unit_exists(name):
            self.create_org_unit(name)

    def get_org_unit(self, name):
        return self.get_objects(search=f'ou={name}')

    def org_unit_exists(self, name):
        return self.subobject_exists_at(f"ou={name}", "organizationalUnit")


class LdapGroupMixin(object):

    def create_group(self, name, organizational_unit, description=None):
        org_unit_dn = f"ou={organizational_unit}"
        self.ensure_org_unit_exists(organizational_unit)
        if self.group_exists(name, organizational_unit):
            raise ConstraintError("Group with such name under this organizational unit already exists")
        dic = self.create_group_dict(f"{name}")
        if description:
            dic['description'] = description
        return self.create_group_from_dict(f"cn={name},{org_unit_dn},{self.BASE_DN}", dic)

    def ensure_group_exists(self, name, organizational_unit, description=None):
        try:
            self.create_group(name, organizational_unit, description)
        except ConstraintError as exc:
            if "already exists" not in str(exc):
                raise

    def get_groups(self, search=None, organizational_unit=None):
        """
        Get objects with object class "posixGroup"

        Args:
            search (str): search filter

        Returns (list):
        """
        relative_pos = f"ou={organizational_unit}" if organizational_unit else None
        return self.get_objects(search=search, relative_pos=relative_pos, obj_class='posixGroup')

    def get_group(self, cname, organizational_unit):
        """
        Get group by cname
        Args:
            cname (str): cname of a group

        Returns:
        """
        return get_single_object(self.get_groups(f"cn={cname}", organizational_unit=organizational_unit))

    def create_group_dict(self, name):
        dic = dict(
            cn=name.encode("ASCII"), objectClass=(b"posixGroup", b"top"), gidNumber=b"500",
        )
        return dic

    def create_group_from_dict(self, fqdn, dic):
        modlist = ldap.modlist.addModlist(dic)
        return self.add_s(fqdn, modlist)

    def group_exists(self, name, organizational_unit):
        return self.subobject_exists_at(f"cn={name},ou={organizational_unit}", "posixGroup")

    def delete_group(self, cname, organizational_unit):
        """
        Delete group by cname and ou

        Args:
            cname (str): group's cname
            organizational_unit (str): group's organizational unit

        Returns:
        """
        return self.delete_object(f"cn={cname},ou={organizational_unit},{self.BASE_DN}")


class LdapServiceMixin(object):

    def create_service(self, name):
        return self.create_group(name=name, organizational_unit="services")


class LdapSpecialMixin(object):
    """
    Special is a posixGroup, child of organizationalUnit ou=special that is just below the base DN.

    A special has machine and display names. A special's DN begins with cn=<machine name>,
    e.g. the full special DN of a presidium special is cn=presidium,ou=special,dc=entint,dc=org.
    There are also cn=board and cn=everyone in the special ou.
    The description attribute of a special stores it's display name, e.g. Presidium in this case.

    The group's gidNumber is not important.
    """

    def get_specials(self, search=None):
        """ Get objects (of posixGroup class) with organizational unit 'special' by given search """
        return self.get_groups(search=search, organizational_unit=self.SPECIAL_GROUP_NAME)

    def get_special(self, machine_name):
        """
        Get special by cname

        Args:
            machine_name (str): special name

        Returns:

        """
        return get_single_object(self.get_specials(f'cn={machine_name}'))

    def create_special(self, machine_name, display_name=None):
        """
        Create special

        Args:
            machine_name (str): special's cname
            display_name (str): special's display name, stored in description

        Returns:

        """
        display_name_bytes = display_name.encode('utf-8') if isinstance(display_name, str) else display_name
        return self.create_group(name=machine_name, organizational_unit="special", description=display_name_bytes)

    def create_all_specials(self, source):
        for dname in source:
            self.create_special(dname)

    def delete_special(self, machine_name):
        """
        Delete special by cname

        Args:
            machine_name (str): special's cname

        Returns:
        """
        return self.delete_group(cname=machine_name, organizational_unit=self.SPECIAL_GROUP_NAME)


class LdapDdeaMixin(object):
    """
    Ddea is a posixGroup, child of organizationalUnit ou=ddea that is just below the base DN.

    A ddea has machine and display names. A ddea's DN begins with cn=<machine name>,
    e.g. the full ddea DN of a it ddea is cn=it,ou=ddea,dc=entint,dc=org.
    There are also cn=res and cn=mar etc in the ddea ou.
    The description attribute of a ddea stores it's display name, e.g. Publishing in this case.

    The group's gidNumber is not important.
    """

    def get_ddeas(self, search=None):
        """ Get objects (of posixGroup class) with organizational unit 'ddea' by given search """
        return self.get_groups(search=search, organizational_unit=self.DDEA_GROUP_NAME)

    def get_ddea(self, machine_name):
        """
        Get ddea by cname

        Args:
            machine_name (str): ddea name

        Returns:

        """
        return get_single_object(self.get_ddeas(f'cn={machine_name}'))

    def create_ddea(self, machine_name, display_name=None):
        """
        Create ddea

        Args:
            machine_name (str): ddea's cname
            display_name (str): ddea's display name, stored in description

        Returns:

        """
        display_name_bytes = display_name.encode('utf-8') if isinstance(display_name, str) else display_name
        return self.create_group(name=machine_name, organizational_unit="ddea", description=display_name_bytes)

    def create_all_ddeas(self, source):
        for dname in source:
            self.create_ddea(dname)

    def delete_ddea(self, machine_name):
        """
        Delete ddea by cname

        Args:
            machine_name (str): ddea's cname

        Returns:
        """
        return self.delete_group(cname=machine_name, organizational_unit=self.DDEA_GROUP_NAME)


class LdapCdeaMixin(object):
    """
    Cdea is a posixGroup, child of organizationalUnit ou=cdea that is just below the base DN.

    A cdea has machine and display names. A cdea's DN begins with cn=<machine name>,
    e.g. the full cdea DN of a cz cdea is cn=cz,ou=cdea,dc=entint,dc=org.
    There are also cn=cz and cn=sk etc in the lm ou.
    The description attribute of a cdea stores it's display name, e.g. Novak in this case.

    The group's gidNumber is not important.
    """

    def get_cdeas(self, search=None):
        """ Get objects (of posixGroup class) with organizational unit 'cdea' by given search """
        return self.get_groups(search=search, organizational_unit=self.CDEA_GROUP_NAME)

    def get_cdea(self, machine_name):
        """
        Get cdea by cname

        Args:
            machine_name (str): cdea name

        Returns:

        """
        return get_single_object(self.get_cdeas(f'cn={machine_name}'))

    def create_cdea(self, machine_name, display_name=None):
        """
        Create cdea

        Args:
            machine_name (str): cdea's cname
            display_name (str): cdea's display name, stored in description

        Returns:

        """
        display_name_bytes = display_name.encode('utf-8') if isinstance(display_name, str) else display_name
        return self.create_group(name=machine_name, organizational_unit="cdea", description=display_name_bytes)

    def create_all_cdeas(self, source):
        for dname in source:
            self.create_cdea(dname)

    def delete_cdea(self, machine_name):
        """
        Delete cdea by cname

        Args:
            machine_name (str): cdea's cname

        Returns:
        """
        return self.delete_group(cname=machine_name, organizational_unit=self.CDEA_GROUP_NAME)


class LdapLmMixin(object):
    """
    lm is a posixGroup, child of organizationalUnit ou=lm that is just below the base DN.

    A lm has machine and display names. A lm's DN begins with cn=<machine name>,
    e.g. the full lm DN of a it lm is cn=it,ou=lm,dc=entint,dc=org.
    There are also cn=cz-res and cn=sk-mar etc in the lm ou.
    The description attribute of a lm stores it's display name, e.g. Publishing in this case.

    The group's gidNumber is not important.
    """

    def get_lms(self, search=None):
        """ Get objects (of posixGroup class) with organizational unit 'lm' by given search """
        return self.get_groups(search=search, organizational_unit=self.LM_GROUP_NAME)

    def get_lm(self, machine_name):
        """
        Get lm by cname

        Args:
            machine_name (str): lm name

        Returns:

        """
        return get_single_object(self.get_lms(f'cn={machine_name}'))

    def create_lm(self, machine_name, display_name=None):
        """
        Create lm

        Args:
            machine_name (str): lm's cname
            display_name (str): lm's display name, stored in description

        Returns:

        """
        display_name_bytes = display_name.encode('utf-8') if isinstance(display_name, str) else display_name
        return self.create_group(name=machine_name, organizational_unit="lm", description=display_name_bytes)

    def create_all_lms(self, source):
        for dname in source:
            self.create_lm(dname)

    def delete_lm(self, machine_name):
        """
        Delete lm by cname

        Args:
            machine_name (str): lm's cname

        Returns:
        """
        return self.delete_group(cname=machine_name, organizational_unit=self.LM_GROUP_NAME)


class LdapDivisionMixin(object):
    """
    Division is a posixGroup, child of organizationalUnit ou=divisions that is just below the base DN.

    A division has machine and display names. A division's DN begins with cn=<machine name>,
    e.g. the full division DN of a publishing division is cn=PUB,ou=divisions,dc=entint,dc=org.
    The description attribute of a division stores it's display name, e.g. Publishing in this case.

    The group's gidNumber is not important.
    """

    def get_divisions(self, search=None):
        """ Get objects (of posixGroup class) with organizational unit 'divisions' by given search """
        return self.get_groups(search=search, organizational_unit=self.DIVISIONS_GROUP_NAME)

    def get_division(self, machine_name):
        """
        Get division by cname

        Args:
            machine_name (str): division name

        Returns:

        """
        return get_single_object(self.get_divisions(f'cn={machine_name}'))

    def create_division(self, machine_name, display_name=None):
        """
        Create division

        Args:
            machine_name (str): division's cname
            display_name (str): division's display name, stored in description

        Returns:

        """
        display_name_bytes = display_name.encode('utf-8') if isinstance(display_name, str) else display_name
        return self.create_group(name=machine_name, organizational_unit="divisions", description=display_name_bytes)

    def create_all_divisions(self, source):
        for dname in source:
            self.create_division(dname)

    def delete_division(self, machine_name):
        """
        Delete division by cname

        Args:
            machine_name (str): division's cname

        Returns:
        """
        return self.delete_group(cname=machine_name, organizational_unit=self.DIVISIONS_GROUP_NAME)


class LdapFranchiseMixin(object):
    """
    Franchise is a posixGroup, child of organizationalUnit ou=franchises that is just below the base DN

    Franchise code is `<country_code>_<something>` where country_code is ISO3166-1-Alpha-2 code
    """

    def get_franchises(self, search=None):
        return self.get_groups(search=search, organizational_unit=self.FRANCHISES_GROUP_NAME)

    def get_franchise(self, code):
        """
        Get franchise by code
        Args:
            code (str): franchise code

        Returns (dict): franchise data dict or raise error if not found or found more than 1 franchise
        """
        return get_single_object(self.get_franchises(f'cn={code}'))

    def create_franchise(self, machine_name, display_name=None):
        """
        Create franchise

        If display name not given, it will be labeled with CLDR country display name
        Args:
            machine_name (str): country code, has to begin with valid ISO3166-1-Alpha-2 code
            display_name (str): franchise display name

        Returns:
        """
        if display_name is None:
            display_name = self.label_franchise(machine_name)
        else:  # check code is valid and exists in Countries codes list
            self.label_franchise(machine_name)
        return self.create_group(machine_name, self.FRANCHISES_GROUP_NAME, description=display_name.encode('utf-8'))

    def delete_franchise(self, machine_name):
        """
        Delete franchise by cname

        Args:
            machine_name (str): franchise's cname

        Returns:
        """
        return self.delete_group(cname=machine_name, organizational_unit=self.FRANCHISES_GROUP_NAME)

    def label_franchise(self, code):
        """
        Get franchise name by country code from constants
        Args:
            code (str): franchise code

        Returns:
        """
        if '_' in code:
            splitted_code = code.split('_')
            if splitted_code[1]:
                code = splitted_code[0]
        country_name = c.COUNTRIES_CODES.get(code, None)
        if not country_name:
            raise KeyError(f"Invalid country code to match '{code}'")
        return country_name

    def create_all_franchises(self, source):
        for code in source:
            self.create_franchise(code)


class LdapTeamMixin(object):
    """
    Team is a posixGroup, child of organizationalUnit ou=teams that is just below the base DN.

    Like division, team has machine and display names. A teams's DN begins with cn=,
    e.g. the full team DN of a Polish publishing division is cn=PL-PUB,ou=teams,dc=entint,dc=org.
    The description attribute of a team stores it's display name, e.g. Poland Publishing in this case.

    The group's gidNumber is not important.
    """

    def get_teams(self, search=None):
        """ Get objects (of posixGroup class) with organizational unit 'teams' by given search """
        return self.get_groups(search=search, organizational_unit=self.TEAMS_GROUP_NAME)

    def get_team(self, name):
        """
        Get team by cname

        Args:
            name (str): team name

        Returns:

        """
        return get_single_object(self.get_teams(f'cn={name}'))

    def create_team(self, machine_name, display_name=None):
        """
        Create team

        Args:
            machine_name (str): team's cname
            display_name (str): team's display name, stored in description

        Returns:

        """
        display_name_bytes = display_name.encode('utf-8') if isinstance(display_name, str) else display_name
        return self.create_group(name=machine_name, organizational_unit="teams", description=display_name_bytes)

    def delete_team(self, machine_name):
        """
        Delete team by cname

        Args:
            machine_name (str): team's cname

        Returns:
        """
        return self.delete_group(machine_name, organizational_unit=self.TEAMS_GROUP_NAME)

    @staticmethod
    def make_team_display_name(franchise_name, division_name):
        """
        Compose team display name from franchise and division display names
        Args:
            franchise_name (str): display name of franchise
            division_name (str): display name of division

        Returns:
        """
        franchise_name = get_str(franchise_name)
        division_name = get_str(division_name)
        return "{} {}".format(franchise_name, division_name)

    @staticmethod
    def make_team_machine_name(franchise_name, division_name):
        """
        Compose team machine name from franchise and division machine names
        Args:
            franchise_name (str): machine name of franchise
            division_name (str): machine name of division

        Returns:
        """
        franchise_name = get_str(franchise_name)
        division_name = get_str(division_name)
        return "{}-{}".format(franchise_name, division_name)

    def get_team_component_units(self, machine_name):
        """
        Get composing franchise and division from team cn
        Args:
            team (dict): ldap team

        Returns:
        """
        franchise_name, division_name = get_str(machine_name).split('-', 1)
        if not all([franchise_name, division_name]):
            raise ObjectDoesNotExist
        franchise = self.get_franchise(franchise_name)
        division = self.get_division(division_name)
        return franchise, division


def ensure_org_sanity(edap, source=None):
    if source is None:
        source = dict()

    edap.ensure_org_unit_exists(edap.FRANCHISES_GROUP_NAME)
    edap.ensure_org_unit_exists(edap.DIVISIONS_GROUP_NAME)
    edap.ensure_org_unit_exists(edap.SERVICES_GROUP_NAME)
    edap.ensure_org_unit_exists(edap.TEAMS_GROUP_NAME)
    edap.ensure_org_unit_exists("people")
    edap.ensure_org_unit_exists(edap.DDEA_GROUP_NAME)
    edap.ensure_org_unit_exists(edap.CDEA_GROUP_NAME)
    edap.ensure_org_unit_exists(edap.LM_GROUP_NAME)
    edap.ensure_org_unit_exists(edap.SPECIAL_GROUP_NAME)
    edap.create_all_divisions(source.get("divisions", []))
    edap.create_all_franchises(source.get("franchises", []))


def get_not_matching_teams_by_cn(edap):
    """
    Get teams that not correspond to existing franchises and divisions by cn

    Team cn must be constructed from existing division and franchise cns <franchise_cn>_<division_cn>
    For example if there is PL-PUB team, then there needs to be a country PL and a division PUB
    """
    not_corresponding_teams = []
    teams = edap.get_teams()
    for team in teams:

        team_machine_name = team['cn'][0]
        try:
            edap.get_team_component_units(team_machine_name)
        except (ObjectDoesNotExist, MultipleObjectsFound):
            not_corresponding_teams.append(team)
            continue

    return not_corresponding_teams


def get_not_matching_teams_by_description(edap):
    """
    Get teams that not correspond to existing franchises and divisions by descriiption

    Team description must be constructed from existing division and franchise descriptions
    <franchise_description>_<division_description>
    For example if there is Poland and Publishing, it should be 'Poland Publishing' team, but not 'Polish Publishing'
    """
    not_corresponding_teams = []
    teams = edap.get_teams()
    for team in teams:
        team_machine_name = team['cn'][0]
        team_display_name = get_str(team['description'][0])

        try:
            franchise, division = edap.get_team_component_units(team_machine_name)
        except (ObjectDoesNotExist, MultipleObjectsFound):
            not_corresponding_teams.append(team)
            continue

        expected_display_name = edap.make_team_display_name(franchise['description'][0], division['description'][0])
        if team_display_name != expected_display_name:
            not_corresponding_teams.append(team)

    return not_corresponding_teams


def update_parser(parser=None):
    if parser is None:
        parser = argparse.ArgumentParser()
    parser.add_argument("hostname")
    parser.add_argument("--password", "-p")
    parser.add_argument("--admin-dn", "-u")
    return parser


class Edap(LdapObjectsMixin, LdapGroupMixin, OrganizationalUnitMixin, LdapPostfixUserMixin,
           LdapTeamMixin, LdapFranchiseMixin, LdapDivisionMixin, LdapServiceMixin,LdapSpecialMixin,
           LdapDdeaMixin, LdapCdeaMixin, LdapLmMixin):

    def __init__(self, hostname, admin_cn, password, domain=None):
        if domain is None:
            domain = "example.com"
        domain_components = domain.split(".")
        basedn_components = [f"dc={c}" for c in domain_components]
        self.BASE_DN = ",".join(basedn_components)

        admin_dn = f"{admin_cn},{self.BASE_DN}"
        self.ldap = ldap.initialize(f"ldap://{hostname}")
        self.ldap.bind_s(admin_dn, password)

        self.PEOPLE_GROUP = f"ou=people,{self.BASE_DN}"

        self.DIVISIONS_GROUP_NAME = "divisions"
        self.DIVISIONS_OU = f"ou={self.DIVISIONS_GROUP_NAME}"
        self.DIVISIONS_GROUP = f"{self.DIVISIONS_OU},{self.BASE_DN}"

        self.DDEA_GROUP_NAME = "ddea"
        self.DDEA_OU = f"ou={self.DDEA_GROUP_NAME}"
        self.DDEA_GROUP = f"{self.DDEA_OU},{self.BASE_DN}"

        self.CDEA_GROUP_NAME = "cdea"
        self.CDEA_OU = f"ou={self.CDEA_GROUP_NAME}"
        self.CDEA_GROUP = f"{self.CDEA_OU},{self.BASE_DN}"

        self.LM_GROUP_NAME = "lm"
        self.LM_OU = f"ou={self.LM_GROUP_NAME}"
        self.LM_GROUP = f"{self.LM_OU},{self.BASE_DN}"

        self.SPECIAL_GROUP_NAME = "special"
        self.SPECIAL_OU = f"ou={self.SPECIAL_GROUP_NAME}"
        self.SPECIAL_GROUP = f"{self.SPECIAL_OU},{self.BASE_DN}"

        self.TEAMS_GROUP_NAME = "teams"
        self.TEAMS_OU = f"ou={self.TEAMS_GROUP_NAME}"
        self.TEAMS_GROUP = f"{self.TEAMS_OU},{self.BASE_DN}"

        self.FRANCHISES_GROUP_NAME = "franchises"
        self.FRANCHISES_OU = f"ou={self.FRANCHISES_GROUP_NAME}"
        self.FRANCHISES_GROUP = f"{self.FRANCHISES_OU},{self.BASE_DN}"

        self.SERVICES_GROUP_NAME = "services"
        self.SERVICES_OU = f"ou={self.SERVICES_GROUP_NAME}"
        self.SERVICES_GROUP = f"{self.SERVICES_OU},{self.BASE_DN}"

    def add_s(self, *args, **kwargs):
        return self.ldap.add_s(*args, **kwargs)

    def modify_s(self, *args, **kwargs):
        return self.ldap.modify_s(*args, **kwargs)

    def search_s(self, *args, **kwargs):
        return self.ldap.search_s(*args, **kwargs)

    def unbind_s(self):
        return self.ldap.unbind_s()

    def delete_s(self, *args, **kwargs):
        return self.ldap.delete_s(*args, **kwargs)


if __name__ == "__main__":
    parser = update_parser()
    args = parser.parse_args()

    edap = Edap(args.hostname, args.admin_dn, args.password)
