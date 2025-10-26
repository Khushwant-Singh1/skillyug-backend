# Admin Creation Scripts

These scripts create admin users for the Skillyug 2.0 platform with NextAuth integration.

## Available Scripts

1. **`create-admin-simple`** - Creates admin in database and outputs NextAuth user object
2. **`update-nextauth-admin`** - Creates admin in database and automatically updates NextAuth configuration
3. **`create-admin`** - Original script (for Supabase integration)

## Prerequisites

1. Make sure you have the required environment variables set up
2. Install dependencies: `pnpm install`
3. Ensure your database is migrated: `pnpm run db:migrate`

## Required Environment Variables

```bash
# Required
ADMIN_EMAIL=admin@skillyug.com
ADMIN_PASSWORD=your_secure_password_here

# Optional
ADMIN_FULL_NAME=Admin User Name
FORCE_UPDATE=true  # Set to update existing admin
```

## Usage

### Recommended: Auto-update NextAuth (Recommended)
```bash
# Creates admin in database and automatically updates NextAuth configuration
ADMIN_EMAIL=admin@skillyug.com ADMIN_PASSWORD=securepassword123 pnpm run update-nextauth-admin
```

### Manual NextAuth Update
```bash
# Creates admin in database and outputs NextAuth user object to copy manually
ADMIN_EMAIL=admin@skillyug.com ADMIN_PASSWORD=securepassword123 pnpm run create-admin-simple
```

### With Full Name
```bash
ADMIN_EMAIL=admin@skillyug.com ADMIN_PASSWORD=securepassword123 ADMIN_FULL_NAME="John Admin" pnpm run update-nextauth-admin
```

### Update Existing Admin
```bash
ADMIN_EMAIL=admin@skillyug.com ADMIN_PASSWORD=newpassword123 FORCE_UPDATE=true pnpm run update-nextauth-admin
```

### Using .env file
Create a `.env` file in the Backend directory:
```env
ADMIN_EMAIL=admin@skillyug.com
ADMIN_PASSWORD=securepassword123
ADMIN_FULL_NAME=Admin User
```

Then run:
```bash
pnpm run update-nextauth-admin
```

## What the Script Does

1. **Validates Environment Variables**: Checks for required environment variables
2. **Validates Input**: Validates email format and password strength
3. **Creates Supabase User**: Creates user in Supabase Auth with admin privileges
4. **Creates Database Profile**: Creates corresponding user profile in the local database
5. **Logs Admin Action**: Records the admin creation action for audit purposes
6. **Handles Existing Users**: Can update existing admin users if `FORCE_UPDATE=true`

## Security Notes

- The script uses the Supabase Service Role Key, which has admin privileges
- Passwords should be at least 8 characters long
- The script automatically sets `email_confirm: true` for the admin user
- Admin actions are logged for audit purposes

## Troubleshooting

### Common Issues

1. **Missing Environment Variables**
   - Ensure all required environment variables are set
   - Check that Supabase credentials are correct

2. **Database Connection Issues**
   - Ensure the database is running and accessible
   - Run `pnpm run db:migrate` to ensure schema is up to date

3. **Supabase Auth Issues**
   - Verify the Supabase URL and Service Role Key
   - Check that the Supabase project is properly configured

4. **User Already Exists**
   - Use `FORCE_UPDATE=true` to update existing users
   - Or delete the existing user first

### Error Messages

- `❌ Missing required environment variables`: Set the required environment variables
- `❌ Invalid email format`: Use a valid email address
- `❌ Password must be at least 8 characters long`: Use a stronger password
- `❌ Supabase auth error`: Check Supabase credentials and configuration

## Example Output

```
🚀 Starting admin user creation...

📋 Admin Credentials:
   Email: admin@skillyug.com
   Full Name: Admin User
   Password: ************

🔐 Creating admin user in Supabase...
✅ Admin user created in Supabase Auth
   User ID: 12345678-1234-1234-1234-123456789012
   Email: admin@skillyug.com

📝 Creating admin profile in database...
✅ Admin profile created in database
   Profile ID: 12345678-1234-1234-1234-123456789012
   Full Name: Admin User
   User Type: ADMIN

✅ Admin action logged

🎉 Admin user created successfully!

📊 Admin Details:
   ID: 12345678-1234-1234-1234-123456789012
   Email: admin@skillyug.com
   Full Name: Admin User
   User Type: ADMIN

🔑 You can now login with these credentials
```
