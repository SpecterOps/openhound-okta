-- Create the table if it does not exist (this usually means the resource was not collected)
CREATE TABLE IF NOT EXISTS __SCHEMA__.privileged_users (
    id VARCHAR
);

INSERT INTO __SCHEMA__.principals_with_admin_roles
SELECT DISTINCT id, 'user' AS principal_type
FROM __SCHEMA__.privileged_users
