import re
import collections

import edap


def get_memberships_from_groups(all_users, groups):
    """
    Given set of all users and a mapping of group -> set of users in the particular group,
    return mappings:

    * country -> set of users in the country, and
    * division -> set of users in that division.
    """
    countries = collections.defaultdict(set)
    divisions = collections.defaultdict(set)

    for group, members in groups.items():
        for member in members:
            if member not in all_users:
                continue
            user_uid = name2uid(member)
            assign_membership(user_uid, group, countries, divisions)

    return countries, divisions


def assign_membership(uid, group_name, countries, divisions):
    """
    Declare that a user belongs to a group.

    Check out the group name, and if it determines that it is a
    country / division name, add the user ID to the list of users
    of a particular country / division.
    """
    new_country = extract_country(group_name)
    if new_country:
        countries[new_country].add(uid)

    new_division = extract_division(group_name)
    if new_division:
        divisions[new_division].add(uid)


def extract_division(group_name):
    """
    Assume that a division-associated e-mail has one of forms:

    * division-<division ID>@...
    * team-...-<division ID>@...
    * ddea-<division ID>@...

    Then, extract and return the division ID.
    """
    division = None
    if group_name.startswith("division-"):
        division = re.sub(r"^division-(\w+)@.*", r"\1", group_name)
    elif group_name.startswith("team-"):
        division = re.sub(r"^team-\w+-(\w+)@.*", r"\1", group_name)
    elif group_name.startswith("ddea-"):
        division = re.sub(r"^ddea-(\w+)@.*", r"\1", group_name)
    return division


def extract_country(group_name):
    """
    Assume that a country-associated e-mail has one of forms:

    * country-<country ID>@...
    * team-<country ID>-...@...
    * cdea-<countr ID>@...

    Then, extract and return the country ID.
    """
    country = None
    if group_name.startswith("country-"):
        country = re.sub(r"^country-(\w+)@.*", r"\1", group_name)
    elif group_name.startswith("team-"):
        country = re.sub(r"^team-(\w+)-\w+@.*", r"\1", group_name)
    elif group_name.startswith("cdea-"):
        country = re.sub(r"^cdea-(\w+)@.*", r"\1", group_name)
    return country


def name2uid(name):
    """
    Given a user's e-mail, strip the trailing @... and claim the rest as user ID.
    """
    return re.sub(r"@.*", "", name)


def make_user_from_dict(bound_ldap, dic):
    """
    Make a LDAP user entry given a dictionary with "uid", "givenName" and "sn" members.
    """
    return edap.add_user(bound_ldap, dic["uid"], dic["givenName"], dic["sn"], "foobar")
