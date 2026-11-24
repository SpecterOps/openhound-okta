CREATE OR REPLACE TABLE __SCHEMA__.non_admin_users AS
SELECT id FROM __SCHEMA__.users
WHERE id NOT IN (
    SELECT id FROM __SCHEMA__.principals_with_admin_roles
    WHERE principal_type = 'user'
)
