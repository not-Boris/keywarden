Next steps:

Certificate Generation:
- User account is created
- User can input SSH pubkey into profile page
- Keywarden creates signed SSH Certificate from User's pubkey and Keywarden CA

Grant:
- User requests access to target server
- Access request approved
- User has linux account created and has key / cert trusted by target server
- User can log into account

Revocation:
- User has access expire or revoked
- Keywarden removes key / cert from target server, or invalidates on Keywarden's side
- Keywarden removes object permissions
- User cannot access server anymore


Permissions:

Administrator:
- Everything

Auditor:
- Can exclusively view audit logs of servers they have access to via request.

User:



Access Requests:

- Can use Shell?
- Can view logs?
- Can have user account?
