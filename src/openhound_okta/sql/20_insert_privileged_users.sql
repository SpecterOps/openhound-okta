INSERT INTO __SCHEMA__.principals_with_admin_roles
SELECT DISTINCT id, 'user' AS principal_type
FROM __SCHEMA__.privileged_users
