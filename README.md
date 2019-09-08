# edap

## Description

EDAP stands for Enterprisey Directory Access Protocol.
EDAP is just a LDAP wrapper - it provides higher-level LDAP interface for organizations that have multi-dimensional subdivision layout.

For example, they may be organized by countries, projects, divisions, etc. and an org member may belong to more of those subdivisions.
Bob may belong to German Operations and work in the Wildlife project, and Alice may be Polish Develpment and Publishing, not working on any project.

This project aims to make the user/group management and import/export operations easy.

## Tests

1. Go into the `docker` directory, execute `docker-compose up -d`
1. When everything finishes, run `bash exec_test.sh` in there.
1. First run may fail, so call the script again. You are set now!

## Requirements

Requires: `pyldap`
