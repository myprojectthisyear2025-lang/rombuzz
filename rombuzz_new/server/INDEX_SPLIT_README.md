# RomBuzz Backend Split (prep for modularization)

- Entry file left intact: `server/index.js` (so Render deploy keeps working)
- The script created/updated these files from your header sections:
  - `config/cloudinary.js`
  - `config/config.js`
  - `config/cors.js`
  - `config/sendgrid.js`
  - `models/db.lowdb.js`
  - `models/migrations.js`
  - `models/write-guard.js`
  - `routes/account.js`
  - `routes/auth-middleware.js`
  - `routes/auth.js`
  - `routes/buzz.js`
  - `routes/microbuzz.js`
  - `routes/misc.js`
  - `routes/notifications.js`
  - `routes/profile.js`
  - `routes/settings.js`
  - `routes/social.js`
  - `routes/users.js`
  - `sockets/calls.js`
  - `sockets/connection.js`
  - `sockets/index.js`
  - `sockets/meet-realtime.js`
  - `utils/helpers.js`
  - `utils/jwt.js`

## Next steps (optional, later)
1. Gradually refactor each generated file to export functions/routers.
2. Replace LowDB usage in `models/db.lowdb.js` with Mongoose models.
3. Create `config/db.js` for Mongo connection and wire models.
4. Once routes export routers, update `server/index.js` to `app.use(...)` them.
