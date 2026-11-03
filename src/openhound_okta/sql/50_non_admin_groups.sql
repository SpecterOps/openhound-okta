CREATE OR REPLACE TABLE __SCHEMA__.non_admin_groups AS
SELECT id FROM __SCHEMA__.groups
WHERE id NOT IN (
    SELECT id FROM __SCHEMA__.principals_with_admin_roles
    WHERE principal_type = 'group'
)
