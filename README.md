# MyrtlePortal

A web server to view a directory. Authentication, permissions, administration, etc.

Beware: this code is really ugly. It uses spaces, it's all in one file, and it's spaghetti code by any standard. However, I wrote it a long time ago and want to archive it here.

## Run

```bash
yarn install
yarn start
```

Requires a MySQL-compatible server running. The database, credentials, host, etc are somewhere in `server.ts`–not sure exactly where.
