-- Create the table if it does not exist (this usually means the resource was not collected)
CREATE TABLE IF NOT EXISTS __SCHEMA__.client_role_assignments (
    source_id VARCHAR,
    status VARCHAR,
    assignment_type VARCHAR
);

INSERT INTO __SCHEMA__.principals_with_admin_roles
SELECT source_id AS id, 'client' AS principal_type
FROM __SCHEMA__.client_role_assignments
WHERE status = 'ACTIVE' AND assignment_type = 'CLIENT'
