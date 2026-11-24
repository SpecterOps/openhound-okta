INSERT INTO __SCHEMA__.principals_with_admin_roles
SELECT source_id AS id, 'client' AS principal_type
FROM __SCHEMA__.client_role_assignments
WHERE status = 'ACTIVE' AND assignment_type = 'CLIENT'
