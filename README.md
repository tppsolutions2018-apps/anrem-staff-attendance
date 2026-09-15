# ANREM Staff Attendance and Report

All Nations Revival Evangelistic Ministries (ANREM) branded staff attendance system.

## Deployment
1. Create a new GitHub repository, e.g. `anrem-staff-attendance`.
2. Upload all files in this folder, preserving `public/` and `server/` directories.
3. Deploy the repository with Render using `render.yaml`.
4. Set `ADMIN_USER` and `ADMIN_PASS` in Render. Do not commit the Admin password to GitHub.
5. Render will create a separate PostgreSQL database named `anrem-staff-attendance-db`.

This deployment is separate from the CAC Wonders Assembly attendance system.
