#!/usr/bin/env bash
set -euo pipefail

# Setup LDAP test users and groups

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Creating LDAP organizational units and test users..."

# Create OUs and users via ldapadd
docker compose exec -T openldap ldapadd -x -D "cn=admin,dc=test,dc=local" -w adminpassword << 'EOF'
# Create People OU
dn: ou=people,dc=test,dc=local
objectClass: organizationalUnit
ou: people

# Create Groups OU
dn: ou=groups,dc=test,dc=local
objectClass: organizationalUnit
ou: groups

# Test user 1 - regular user
dn: uid=testuser,ou=people,dc=test,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: testuser
sn: User
givenName: Test
cn: Test User
displayName: Test User
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/testuser
mail: testuser@test.local
userPassword: testpassword

# Test user 2 - admin user
dn: uid=adminuser,ou=people,dc=test,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: adminuser
sn: Admin
givenName: Test
cn: Test Admin
displayName: Test Admin
uidNumber: 10001
gidNumber: 10000
homeDirectory: /home/adminuser
mail: adminuser@test.local
userPassword: adminpassword

# Developers group
dn: cn=developers,ou=groups,dc=test,dc=local
objectClass: posixGroup
cn: developers
gidNumber: 20000
memberUid: testuser

# Admins group
dn: cn=admins,ou=groups,dc=test,dc=local
objectClass: posixGroup
cn: admins
gidNumber: 20001
memberUid: adminuser
EOF

echo "LDAP setup complete!"
echo ""
echo "Test users created:"
echo "  - testuser / testpassword (member of: developers)"
echo "  - adminuser / adminpassword (member of: admins)"
