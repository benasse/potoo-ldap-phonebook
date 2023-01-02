# Potoo-ldap-phonebook
Expose wazo directory throught ldap

## Installation
```
wazo-plugind-cli -c 'install git https://github.com/benasse/potoo'
```

## Usage
This plugin listens on port 10389 and allows an endpoint to query through the ldap protocol the content of the wazo server.

Currently the search is performed on the following items:
- all user lines
- the mobile phone number of the users
- the groups
- queues

The default user is `uid=potoo`, the default password is randomly generated and stored in the file `/etc/systemd/system/potoo-ldap-phonebook.service`.

It is possible to filter the results returned by the plugin according to the `cn` and `telephoneNumber` attributes.

The base DN of the search must be the following: `ou=phonebook,cn=potoo,dc=pm`

Below are query example made with ldap search:
```
ldapsearch -x -b "ou=phonebook,cn=potoo,dc=pm" -H ldap://localhost:10389 -D uid=potoo -w MiCht+47QF496zoeyxa= "(cn=*test*)"
ldapsearch -x -b "ou=phonebook,cn=potoo,dc=pm" -H ldap://localhost:10389 -D uid=potoo -w MiCht+47QF496zoeyxa= "(telphoneNumber=800*)"
```

## Limitaiton
Only simple ldap filters are supported

## Other
Inspired by https://github.com/a1comms/freepbx-ldap
