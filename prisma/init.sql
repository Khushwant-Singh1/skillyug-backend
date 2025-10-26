-- Initialize database schema if needed
CREATE SCHEMA IF NOT EXISTS public;

-- Set default permissions
GRANT ALL ON SCHEMA public TO skillyug_user;
GRANT ALL ON SCHEMA public TO public;