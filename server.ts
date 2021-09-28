import { PoolConnection, MysqlError } from 'mysql';
import { Request, Response } from 'express';
import { Dirent } from 'fs';

export {};

import express = require('express');
import expresshbs = require('express-handlebars');
import cookieParser = require('cookie-parser');
import bodyParser = require('body-parser');
import mysql = require('mysql');

import childprocess = require('child_process');

import isImage = require('is-image');
import isVideo = require('is-video');
import mime = require('mime-types');
import tar = require('tar');
import xz = require('xz');
import archiver = require('archiver');

import multiparty = require('multiparty');
import isemail = require('isemail');

import { promisify } from 'util';
import luxon = require('luxon');
import fs = require('fs-extra');
import realfs = require('fs');
import path = require('path');
import bcrypt = require('bcryptjs');
import crypto = require('crypto');
// #region define logging functions
const logfile = fs.openSync((process.env.nolog ?? 'true') ? '/dev/null' : path.join(process.cwd(), 'lastlog'), 'w');
fs.writeSync(logfile, `Start server at ${new Date().toLocaleString()}\n`);
const colors = require('colors/safe');
const output = function (type: string, message: string, options: outputOptions) {
  try { fs.writeSync(logfile, `[${new Date().toTimeString().split(' ')[0]}] [${type.toUpperCase()}] ${message}${(options.newline ?? true) ? '\n' : ''}`); } catch (e) {
    // the fd has been closed; not a problem.
  }
  if (options.logOnly ?? false) return;
  if (options.overwrite) process.stdout.write('\r');
  process.stdout.write(`[${new Date().toTimeString().split(' ')[0]}] `);
  process.stdout.write(colors.bold[options.color ?? 'black'](`[${type.toUpperCase()}] `));
  process.stdout.write(colors[options.color ?? 'black'](message));
  if (options.newline ?? true) process.stdout.write('\n');
};
const error = (message: string, options: loggerOptions = { overwrite: false, newline: true }) => output('err', message, { overwrite: options.overwrite ?? false, newline: options?.newline ?? true, color: 'red' });
const warn = (message: string, options: loggerOptions = { overwrite: false, newline: true }) => output('warn', message, { overwrite: options.overwrite ?? false, newline: options?.newline ?? true, color: 'yellow' });
const info = (message: string, options: loggerOptions = { overwrite: false, newline: true }) => output('info', message, { overwrite: options.overwrite ?? false, newline: options?.newline ?? true, color: 'blue' });
const log = (message: string, options: loggerOptions = { overwrite: false, newline: true }) => output('log', message, { overwrite: options.overwrite ?? false, newline: options?.newline ?? true, color: 'black' });
const srv = (message: string, options: loggerOptions = { overwrite: false, newline: true }) => output('srv', message, { overwrite: options.overwrite ?? false, newline: options?.newline ?? true, color: 'magenta', logOnly: true });
// #endregion

log('Init Express');
const app = express();
log('Init DB Connection');
const connection = mysql.createPool({
  connectionLimit: 50,
  host: 'localhost',
  user: 'test',
  password: 'test',
  database: 'myserver',
  multipleStatements: true
});
connection.getConnection(function (err: MysqlError, connection: PoolConnection) {
  if (err && err.code === 'ECONNREFUSED') {
    process.stdout.write(colors.bold.underline.brightRed('Start MariaDB, you lickspittling mumpsimus!\n'));
    process.exit(0);
  } else {
    connection.release();
  }
});

const getHashedPassword = (password: string): string => {
  return bcrypt.hashSync(password, bcrypt.genSaltSync(10));
};
const authTokens: Record<string, string> = {}; // will reset when server is restarted.
const resourceHashes: Map<string, string> = new Map();

// app.use(function (req: Request, res: Response, next: () => void) {
//   if (req.secure) next(); else res.redirect(`https://${req.headers.host}${req.url}`);
// });

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use((req: Request, res: Response, next: () => void) => {
  req.user = authTokens[req.cookies.token];
  next();
});
app.engine('hbs', expresshbs({ extname: '.hbs' }));
app.set('view engine', 'hbs');

app.all('/**', (req: Request, res: Response, next: () => void) => { srv(`${req.method} ${req.url}`); next(); });

app.get('/', (req: Request, res: Response) => { if (req.user) res.redirect('/welcome'); else res.render('home', { title: 'MyrtlePortal', styles: ['centered'] }); });

const genericResourceHandler = async (req: Request, res: Response) => {
  if (await new Promise((resolve, reject) => { try { fs.exists(path.join(process.cwd(), req.url), resolve); } catch (err) { reject(err); } })) res.sendFile(path.join(process.cwd(), req.url)); else res.status(404).render('error', { title: 'Error', error: '404 Not Found' });
};
app.get('/res/style/*.less', (req: Request, res: Response) => res.status(404).render('error', { title: 'Error', error: '404 Not Found' }));
app.get('/res/js/.eslintrc', (req: Request, res: Response) => res.status(404).render('error', { title: 'Error', error: '404 Not Found' }));
app.get('/res/*/*', genericResourceHandler);
app.get('/favicon.ico', genericResourceHandler);

app.get('/hres/:hash', (req: Request, res: Response) => {
  if (resourceHashes.has(req.params.hash)) {
    nocache(res);
    const fileStream = fs.createReadStream(resourceHashes.get(req.params.hash) ?? ''); // will never be undefined (and therefore never `''`) since we check it two lines above.
    fileStream.on('end', function () {
      resourceHashes.delete(req.params.hash);
    });
    fileStream.pipe(res);
  } else {
    res.status(404).render('error', { title: 'Error', error: '404 Not Found' });
  }
});

/**
 * Disable caching for the resource via HTTP headers.
 * @param {Response} obj - The response object from the Express callback.
 */
const nocache = (obj: Response) => {
  obj.header('Cache-Control', 'no-cache, no-store, must-revalidate');
  obj.header('Pragma', 'no-cache');
  obj.header('Expires', '0');
};

// define middlewares to require authorization.
const requireAuth = (req: Request, res: Response, next: () => void) => {
  if (req.user) {
    next();
  } else {
    res.redirect('/login');
  }
};
const requireAdmin = async (req: Request, res: Response, next: () => void) => {
  if (req.user) {
    if (await new Promise((resolve, reject) => connection.query('SELECT admin FROM users WHERE username = ?', [req.user], function (err: MysqlError | null, results: Record<string, boolean>[]) { if (err) reject(err); else resolve(!!results[0].admin); }))) {
      next();
    } else {
      res.status(404).render('error', { title: 'Error', error: '404 Not Found' });
    }
  } else {
    res.redirect('/login');
  }
};

/* eslint-disable-next-line func-call-spacing */
app.get ('/register', (req: Request, res: Response) => { nocache(res); res.render('register', { user: req.user, title: 'Register' }); });
app.post('/register', async (req: Request, res: Response) => {
  try {
    let failed = false;
    const fail = (type = '', reason = '') => {
      if (!failed) {
        srv(`From ${req.ip} on ${req.url}: Validation failed for field '${type}': ${reason}`);
        nocache(res);
        const savedValues: Record<string, string> = {
          savedEmail: email,
          savedUsername: username,
          savedPassword: password,
          savedConfirm: confirmPassword
        };
        delete savedValues[`saved${type.charAt(0).toUpperCase() + type.slice(1)}`]; // remove the saved value for the problematic property.
        if (type === 'password') delete savedValues.savedConfirm; // also remove confirmation if the password is invalid.
        res.render('register', { [`${type}Message`]: reason, title: 'Register', ...savedValues });
        failed = true;
      }
    };

    const { email, username, password, confirmPassword } = req.body;

    if (!email || !username || !password || !confirmPassword) res.status(400).render('error', { title: 'Error', error: '400 Bad Request' }); else {
      if (await new Promise((resolve, reject) => {
        connection.query('SELECT count(*) FROM users WHERE username = ?', [username], function (err: MysqlError | null, results: Record<string, number>[]) {
          if (err) { reject(err); } else {
            resolve(results[0]['count(*)'] !== 0);
          }
        });
      })) fail('username', 'Username taken.');
      if (username.length < 6) fail('username', 'Username must be at least 6 characters.');
      const invalidCharMatches = username.match(/[^\d\w-.]/g);
      if (invalidCharMatches !== null) fail('username', `Invalid character at position ${invalidCharMatches.index + 1}. Usernames may only contain alphanumerics, dashes, underscores, and periods.`);
      if (password.length < 8) fail('password', 'Password must be at least eight characters.');
      if (!(/[A-Z]/.test(password))) fail('password', 'Password must contain at least one capital letter.');
      if ((password.match(/\d/g) ?? []).length < 2) fail('password', 'Password must contain at least two numbers.');
      if ((password.match(/[^\d\w\s]/g) ?? []).length < 2) fail('password', 'Password must contain at least two special characters.');
      if (!isemail.validate(email)) fail('email', "Email doesn't look right.");
      if (confirmPassword !== password) fail('confirm', 'Passwords do not match.');

      if (!failed) {
        srv(`From ${req.ip}: Successful registration with data as follows:\n - Username: ${username}\n - Password: ${password}\n - Email: ${email}`);
        connection.query('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', [username, getHashedPassword(password), email], function (err: MysqlError | null) {
          if (err) throw err;
        });
        res.redirect('/login');
      }
    }
  } catch (e) {
    const { email, username, password, confirmPassword } = req.body;
    if (!email || !username || !password || !confirmPassword) res.status(400).render('error', { title: 'Error', error: '400 Bad Request' }); else {
      const ecode = Date.now();
      warn(`Internal server error on /register (code ${req.ip}+${ecode}): ${e.stack ? `\n${e.stack}` : `${e.name}: ${e.message}`}`);
      nocache(res);
      res.status(500).render('register', {
        title: 'Register',
        savedEmail: email,
        savedUsername: username,
        savedPassword: password,
        savedConfirm: confirmPassword,
        failMessage: `We've encountered an internal server error while processing this request. Please try again later, and contact the site owner and mention the error code '${req.ip}+${ecode}'.`
      });
    }
  }
});

/* eslint-disable-next-line func-call-spacing */
app.get ('/login', (req: Request, res: Response) => { nocache(res); res.render('login', { user: req.user, title: 'Login' }); });
app.post('/login', async (req: Request, res: Response) => {
  try {
    let failed = false;
    const fail = (type = '', reason = '') => {
      if (!failed) {
        srv(`From ${req.ip} on ${req.url}: Validation failed for field '${type}': ${reason}`);
        nocache(res);
        res.render('login', { [`${type}Message`]: reason, title: 'Login' }); failed = true;
      }
    };

    const { username, password } = req.body;

    // make sure both fields were provided, otherwise send 400 Bad Request.
    if (!username || !password) res.status(400).render('error', { title: 'Error', error: '400 Bad Request' }); else {
      if (req.user) { // replace session if user was previously logged in.
        delete authTokens[req.cookies.authToken];
        res.clearCookie('token');
      }

      switch (await new Promise((resolve, reject) => {
        connection.query('SELECT password FROM users WHERE username = ?', [username], function (err: MysqlError | null, results: Record<string, string>[]) {
          if (err) reject(err); else {
            if (results.length !== 1) {
              resolve(1);
            } else if (!bcrypt.compareSync(password, results[0].password)) {
              resolve(2);
            } else {
              resolve(0);
            }
          }
        });
      })) {
        case 1:
          fail('username', 'Invalid username.');
          break;
        case 2:
          fail('password', 'Incorrect password.');
          break;
      }

      if (!failed) {
        srv(`From ${req.ip}: Successful login as '${username}'`);

        const authToken = crypto.randomBytes(30).toString('hex');
        authTokens[authToken] = username;

        // Give the user their token in the form of a cookie.
        res.cookie('token', authToken);

        // Redirect to the welcome page.
        res.redirect('/welcome');
      }
    }
  } catch (e) {
    const { username, password } = req.body;
    if (!username || !password) res.status(400).render('error', { title: 'Error', error: '400 Bad Request' }); else {
      const ecode = Date.now();
      warn(`Internal server error on /login (code ${req.ip}+${ecode}): ${e.stack ? `\n${e.stack}` : `${e.name}: ${e.message}`}`);
      nocache(res);
      res.status(500).render('login', {
        title: 'Login',
        failMessage: `We've encountered an internal server error while processing this request. Please try again later, and contact the site owner and mention the error code '${req.ip}+${ecode}'.`
      });
    }
  }
});
app.get('/logout', (req: Request, res: Response) => {
  const tokenCopy = req.cookies.token; // atomicity!
  const authTokenCopy = authTokens[req.cookies.token];
  try {
    if (req.user) { // do nothing if the user isn't logged in; just redirect to /login
      delete authTokens[req.cookies.token];
      res.clearCookie('token');
    }
    res.redirect('/login');
  } catch (e) {
    const ecode = Date.now();
    warn(`Internal server error on /logout (code ${req.ip}+${ecode}): ${e.stack ? `\n${e.stack}` : `${e.name}: ${e.message}`}`);
    authTokens[tokenCopy] = authTokenCopy; // rollback.
    res.cookie('token', tokenCopy);
    nocache(res);
    res.status(500).send(`We've encountered an internal server error while processing this request (don't worry; your session was not terminated). Please try again later, and contact the site owner and mention the error code '${req.ip}+${ecode}'.`); // no good place to redirect to...
  }
});

app.get('/welcome', requireAuth, async (req: Request, res: Response) => {
  try {
    const userData: userRow = await new Promise((resolve, reject) => connection.query('SELECT * FROM users WHERE username = ?', [req.user], function (err: MysqlError | null, results: userRow[]) { if (err) reject(err); else resolve(results[0]); }));
    nocache(res);
    res.render('welcome', { user: userData, hasAnyPermissions: userData.view || userData.download || userData.edit, title: 'Home', styles: ['centered'] });
  } catch (e) {
    const ecode = Date.now();
    warn(`Internal server error on /welcome (code ${req.ip}+${ecode}; user '${req.user}'): ${e.stack ? `\n${e.stack}` : `${e.name}: ${e.message}`}`);
    nocache(res);
    res.status(500).send(`We've encountered an internal server error while processing this request. Please try again later, and contact the site owner and mention the error code '${req.ip}+${ecode}'.`); // no good place to redirect to...
  }
});

app.get('/settings', requireAuth, (req: Request, res: Response) => {
  nocache(res);
  res.render('settings', { title: 'Settings' });
});
app.post('/settings', requireAuth, async (req: Request, res: Response) => {
  try {
    let failed = false;
    const fail = (type = '', reason = '') => {
      if (!failed) {
        srv(`From ${req.ip} on ${req.url}: Validation failed for field '${type}': ${reason}`);
        nocache(res);
        res.render('settings', { [`${type}Error`]: reason, title: 'Settings' });
        failed = true;
      }
    };

    if (req.body.username) { // Username change
      if (await new Promise((resolve, reject) => {
        connection.query('SELECT count(*) FROM users WHERE username = ?', [req.body.username], function (err: MysqlError | null, results: Record<string, number>[]) {
          if (err) { reject(err); } else {
            resolve(results[0]['count(*)'] !== 0);
          }
        });
      })) fail('username', 'Username taken.');
      if (req.body.username.length < 6) fail('username', 'Username must be at least 6 characters.');
      const invalidCharMatches = req.body.username.match(/[^a-zA-Z0-9-_.]/g);
      if (invalidCharMatches !== null) fail('username', `Invalid character at position ${invalidCharMatches.index + 1}. Usernames may only contain alphanumerics, dashes, underscores, and periods.`);

      if (!failed) {
        await new Promise((resolve, reject) => { // update the database.
          connection.query('UPDATE users SET username = ? WHERE username = ?', [req.body.username, req.user], function (err: MysqlError | null) { if (err) reject(err); else resolve(); });
        });
        authTokens[req.cookies.token] = req.body.username; // update associated auth token for the user.
        nocache(res);
        res.render('settings', { title: 'Settings', actionNotification: `Successfully changed username from ${req.user} to ${req.body.username}.` });
      }
    } else if (req.body.oldpassword && req.body.newpassword && req.body.confirmpassword) { // Password change
      if (!await bcrypt.compare(req.body.oldpassword, await new Promise((resolve, reject) => {
        connection.query('SELECT password FROM users WHERE username = ?', [req.user], (err: MysqlError | null, results: Record<string, string>[]) => {
          if (err) reject(err); else resolve(results[0].password);
        });
      }))) fail('oldPassword', 'Incorrect password.');
      if (req.body.newpassword.length < 8) fail('newPassword', 'Password must be at least eight characters.');
      if (!(/[A-Z]/.test(req.body.newpassword))) fail('newPassword', 'Password must contain at least one capital letter.');
      if ((req.body.newpassword.match(/\d/g) ?? []).length < 2) fail('newPassword', 'Password must contain at least two numbers.');
      if ((req.body.newpassword.match(/[^\d\w\s]/g) ?? []).length < 2) fail('newPassword', 'Password needs at least two special characters.');
      if (req.body.confirmpassword !== req.body.newpassword) fail('confirmPassword', 'Passwords do not match');

      if (!failed) {
        await new Promise((resolve, reject) => { connection.query('UPDATE users SET password = ? WHERE username = ?', [getHashedPassword(req.body.newpassword), req.user], function (err: MysqlError | null) { if (err) reject(err); else resolve(); }); });
        nocache(res);
        res.render('settings', { title: 'Settings', actionNotification: 'Successfully updated password.' });
      }
    } else if (req.body.email) { // Email change
      if (!isemail.validate(req.body.email)) fail('email', "Email doesn't look right.");

      if (!failed) {
        await new Promise((resolve, reject) => connection.query('UPDATE users SET email = ? WHERE username = ?', [req.body.email, req.user], function (err: MysqlError | null) { if (err) reject(err); else resolve(); }));
        nocache(res);
        res.render('settings', { title: 'Settings', actionNotification: `Successfully changed email to ${req.body.email}` });
      }
    } else if (req.body.action && req.body.action === 'delAcct') { // Account deletion
      await new Promise((resolve, reject) => connection.query('DELETE FROM users WHERE username = ?', [req.user], function (err: MysqlError | null) { if (err) reject(err); else resolve(); }));
      res.redirect('/register');
    } else { // No data provided
      // send 400 and render the page as if no action was taken.
      const userData = await new Promise((resolve, reject) => connection.query('SELECT * FROM users WHERE username = ?', [req.user], function (err: MysqlError | null, results: userRow[]) { if (err) reject(err); else resolve(results[0]); }));
      nocache(res);
      res.status(400).render('settings', { user: userData, title: 'Settings', actionNotification: 'Malformed request; no action taken.' });
    }
  } catch (e) {
    const ecode = Date.now();
    warn(`Internal server error on /settings (code ${req.ip}+${ecode}; user '${req.user}'): ${e.stack ? `\n${e.stack}` : `${e.name}: ${e.message}`}`);
    nocache(res);
    res.status(500).render('settings', {
      title: 'Settings',
      failMessage: `We've encountered an internal server error while processing this request. Please try again later, and contact the site owner and mention the error code '${req.ip}+${ecode}'.`
    });
  }
});

app.get('/adminpanel', requireAdmin, async (req: Request, res: Response) => {
  try {
    if (req.query.user === 'new') { // send interface to add user (C)
      nocache(res);
      res.render('adminpanel_add', {
        title: 'Add User',
        helpers: {
          nowasdate: function () { return luxon.DateTime.fromJSDate(new Date()).toISODate(); },
          nowastime: function () { return luxon.DateTime.fromJSDate(new Date()).toFormat('HH:mm:ss'); }
        }
      });
    } else { // send interface to select users and possibly edit or delete (RUD)
      const users: userRow[] = await new Promise((resolve, reject) => connection.query('SELECT * FROM users', function (err: MysqlError | null, results: userRow[]) { if (err) reject(err); else resolve(results); }));
      nocache(res);
      res.render('adminpanel', {
        users, // @ts-expect-error on next line - We check req.query.user's type ⬇️ right here; TypeScript simply can't comprehend the grammar in this case.
        selectedUser: req.query.hasOwnProperty('user') && typeof req.query.user === 'string' ? users.find(n => { return n.id === parseInt(req.query.user, 10); }) : null,
        helpers: {
          dateof: function (date: Date) { return luxon.DateTime.fromJSDate(date).toISODate(); },
          timeof: function (date: Date) { return luxon.DateTime.fromJSDate(date).toFormat('HH:mm:ss'); },
          equal: function (a: number, b: number) { return (a ?? NaN) === (b ?? NaN); }
        },
        title: 'Admin Panel'
      });
    }
  } catch (e) {
    const ecode = Date.now();
    warn(`Internal server error on /adminpanel (code ${req.ip}+${ecode}; user ${req.user}): ${e.stack ? `\n${e.stack}` : `${e.name}: ${e.message}`}`);
    nocache(res);
    res.status(500).send(`We've encountered an internal server error while processing this request. Please try again later, and contact the site owner and mention the error code '${req.ip}+${ecode}'.`);
  }
});
app.post('/adminpanel', requireAdmin, async (req: Request, res: Response) => {
  try {
    if (req.body.id === 'new') { // add request (C)
      await new Promise((resolve, reject) => connection.query('INSERT INTO users (username, password, created_at, email, view, edit, download, admin) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [req.body.username, getHashedPassword(req.body.password), luxon.DateTime.fromISO(`${req.body.createdAtDate}T${req.body.createdAtTime}`).toJSDate(), req.body.email, (req.body.perms ?? []).includes('view'), (req.body.perms ?? []).includes('edit'), (req.body.perms ?? []).includes('download'), req.body.userType === 'admin'], function (err: MysqlError | null) { if (err) reject(err); else resolve(); }));
      const users: userRow[] = await new Promise((resolve, reject) => connection.query('SELECT * FROM users', function (err: MysqlError | null, results: userRow[]) { if (err) reject(err); else resolve(results); }));
      nocache(res);
      res.render('adminpanel', {
        title: 'Admin Panel',
        users,
        selectedUser: req.query.hasOwnProperty('user') && typeof req.query.user === 'string' ? users[parseInt(req.query.user, 10) - 1] : null,
        helpers: {
          dateof: function (date: Date) { return luxon.DateTime.fromJSDate(date).toISODate(); },
          timeof: function (date: Date) { return luxon.DateTime.fromJSDate(date).toFormat('HH:mm:ss'); },
          not: function (bool: boolean) { return !bool; },
          equal: function (a: number, b: number) { return (a ?? NaN) === (b ?? NaN); }
        },
        actionNotification: `Successfully added user '${req.body.username}'`
      });
    } else if (req.body.delete) { // delete request (D)
      const deletedUsername = await new Promise((resolve, reject) => connection.query('SELECT username FROM users WHERE id = ?', [req.body.id], function (err: MysqlError | null, results: Record<string, string>[]) { if (err) reject(err); else resolve(results[0].username); }));
      await new Promise((resolve, reject) => connection.query('DELETE FROM users WHERE id = ?', [req.body.id], function (err: MysqlError | null) { if (err) reject(err); else resolve(); }));
      const users: userRow[] = await new Promise((resolve, reject) => connection.query('SELECT * FROM users', function (err: MysqlError | null, results: userRow[]) { if (err) reject(err); else resolve(results); }));
      nocache(res);
      res.render('adminpanel', {
        title: 'Admin Panel',
        users,
        selectedUser: null,
        helpers: {
          dateof: function (date: Date) { return luxon.DateTime.fromJSDate(date).toISODate(); },
          timeof: function (date: Date) { return luxon.DateTime.fromJSDate(date).toFormat('HH:mm:ss'); },
          not: function (bool: boolean) { return !bool; },
          equal: function (a: number, b: number) { return (a ?? NaN) === (b ?? NaN); }
        },
        actionNotification: `Successfully deleted user '${deletedUsername}'`
      });
    } else if (!isNaN(parseInt(req.body.id, 10))) { // edit request (U)
      const previousUsername = await new Promise((resolve, reject) => connection.query('SELECT username FROM users WHERE id = ?', [req.body.id], function (err: MysqlError | null, results: Record<string, string>[]) { if (err) reject(err); else resolve(results[0].username); }));
      await new Promise((resolve, reject) => connection.query(
        req.body.password
          ? 'UPDATE users SET username = ?, password = ?, email = ?, created_at = ?, view = ?, edit = ?, download = ?, admin = ? WHERE id = ?'
          : 'UPDATE users SET username = ?, email = ?, created_at = ?, view = ?, edit = ?, download = ?, admin = ? WHERE id = ?',
        req.body.password
          ? [req.body.username, getHashedPassword(req.body.password), req.body.email, luxon.DateTime.fromISO(`${req.body.createdAtDate}T${req.body.createdAtTime}`).toJSDate(), req.body.perms.includes('view'), req.body.perms.includes('edit'), req.body.perms.includes('download'), req.body.userType === 'admin', req.body.id]
          : [req.body.username, req.body.email, luxon.DateTime.fromISO(`${req.body.createdAtDate}T${req.body.createdAtTime}`).toJSDate(), req.body.perms.includes('view'), req.body.perms.includes('edit'), req.body.perms.includes('download'), req.body.userType === 'admin', req.body.id],
        function (err: Error | null) { if (err) reject(err); else resolve(); })
      );
      if (previousUsername === req.user) {
        authTokens[req.cookies.token] = req.body.username;
      }
      const users: userRow[] = await new Promise((resolve, reject) => connection.query('SELECT * FROM users', function (err: MysqlError | null, results: userRow[]) { if (err) reject(err); else resolve(results); }));
      nocache(res);
      res.render('adminpanel', {
        title: 'Admin Panel',
        users,
        selectedUser: req.query.hasOwnProperty('user') && typeof req.query.user === 'string' ? users[parseInt(req.query.user, 10) - 1] : null,
        helpers: {
          dateof: function (date: Date) { return luxon.DateTime.fromJSDate(date).toISODate(); },
          timeof: function (date: Date) { return luxon.DateTime.fromJSDate(date).toFormat('HH:mm:ss'); },
          not: function (bool: boolean) { return !bool; },
          equal: function (a: number, b: number) { return (a ?? NaN) === (b ?? NaN); }
        },
        actionNotification: `Successfully updated user '${req.body.username}${previousUsername !== req.body.username ? ` (was '${previousUsername}')` : ''}'`
      });
    } else { // malformed request: send 400 and render page as if no action was taken
      const users: userRow[] = await new Promise((resolve, reject) => connection.query('SELECT * FROM users', function (err: MysqlError | null, results: userRow[]) { if (err) reject(err); else resolve(results); }));
      nocache(res);
      res.render('adminpanel', {
        title: 'Admin Panel',
        users,
        selectedUser: null,
        helpers: {
          dateof: function (date: Date) { return luxon.DateTime.fromJSDate(date).toISODate(); },
          timeof: function (date: Date) { return luxon.DateTime.fromJSDate(date).toFormat('HH:mm:ss'); },
          not: function (bool: boolean) { return !bool; },
          equal: function (a: number, b: number) { return (a ?? NaN) === (b ?? NaN); }
        },
        actionNotification: 'Malformed request; no action was taken.'
      });
    }
  } catch (e) {
    const ecode = Date.now();
    warn(`Internal server error on /adminpanel (code ${req.ip}+${ecode}): ${e.stack ? `\n${e.stack}` : `${e.name}: ${e.message}`}`);
    // if the issue was with SQL, this will also fail so the error will be "properly" handled.
    const users: userRow[] = await new Promise((resolve, reject) => connection.query('SELECT * FROM users', function (err: MysqlError | null, results: userRow[]) { if (err) reject(err); else resolve(results); }));
    nocache(res);
    res.status(500).render('adminpanel', {
      title: 'Admin Panel',
      users,
      selectedUser: null,
      helpers: {
        dateof: function (date: Date) { return luxon.DateTime.fromJSDate(date).toISODate(); },
        timeof: function (date: Date) { return luxon.DateTime.fromJSDate(date).toFormat('HH:mm:ss'); },
        not: function (bool: boolean) { return !bool; },
        equal: function (a: number, b: number) { return (a ?? NaN) === (b ?? NaN); }
      },
      failMessage: `We've encountered an internal server error while processing this request. Please try again later, and contact the site owner and mention the error code '${req.ip}+${ecode}'.`
    });
  }
});

const fsRouter = express.Router();
const genBreadcrumb = (fPath: string): string => {
  const names = fPath.split('/');
  if (names.length === 1 && names[0] === '') {
    return '<strong>/</strong>';
  } else {
    return names.reduce((acc, el, i) => {
      return `${acc}${acc.length > 0 ? '\u00a0/\u00a0' : '<a href="/portal">/</a>\u00a0'}${i === names.length - 1 ? `<strong>${el}</strong>` : `<a href="/portal/${names.slice(0, i + 1).join('/')}">${el}</a>`}`;
    }, '');
  }
};
// ensure proper access with req.{view|edit|download} object (requires login, naturally; redirect if not logged in).
fsRouter.use(async (req: Request, res: Response, next: () => void) => {
  if (req.user) {
    Object.assign(req, (await new Promise((resolve, reject) => connection.query('SELECT view, edit, download FROM users WHERE username = ?', [req.user], function (err: MysqlError | null, results: Record<string, boolean>[]) { if (err) reject(err); else resolve(results[0]); })))); // add info about view, edit, and download permissions to the request object.
    next();
  } else {
    res.redirect('/login');
  }
});
app.use('/portal', fsRouter);

fsRouter.get('/**', async (req: Request, res: Response, next: () => void) => {
  try {
    if (req.url.includes('..')) {
      next(); // if someone tries to access files outside of the fs folder with relative paths, we'll just tell them it doesn't exist.
    } else if (req.path !== '/' && req.path.slice(-1) === '/') {
      res.redirect(308, `/portal${req.path === '/' ? '' : '/'}${req.path.slice(0, -1)}`); // remove trailing slash if present and redirect with 308 Permanent Redirect (important to be 308 since we want POSTs to be redirected as-is to the canonical URL).
    } else {
      /**
       * The path that the user thinks they're accessing. (no preceding slash; for root it's ''!)
       */
      const requestedApparentPath = req.path.slice(1);
      /**
       * The actual resolved location of the requested file within the filesystem.
       */
      const requestedCanonicalPath = path.join(process.cwd(), 'fs', requestedApparentPath);
      if (await new Promise((resolve, reject) => { try { fs.exists(requestedCanonicalPath, resolve); } catch (e) { reject(e); } })) {
        if (req.query.hasOwnProperty('edit')) {
          if (req.edit) {
            if ((await fs.stat(requestedCanonicalPath)).isFile()) {
              const fileData: basicEntryData = await new Promise((resolve, reject) => connection.query('SELECT name, descr FROM files WHERE path = ?', [requestedApparentPath], function (err: MysqlError | null, results: basicEntryData[]) { if (err) reject(err); else resolve(results[0] ?? {}); }));
              fileData.filename = path.basename(requestedApparentPath);
              nocache(res);
              res.render('fs/edit/file', {
                title: `Editing ${fileData?.name ?? path.basename(requestedApparentPath)}`,
                perms: { view: req.view, edit: req.edit, download: req.download },
                breadcrumb: genBreadcrumb(requestedApparentPath),
                requestedApparentPath,
                entryData: fileData
              });
            } else {
              const dirData: basicEntryData = await new Promise((resolve, reject) => connection.query('SELECT name, descr FROM dirs WHERE path = ?', [requestedApparentPath], function (err: MysqlError | null, results: basicEntryData[]) { if (err) reject(err); else resolve(results[0] ?? {}); }));
              dirData.filename = path.basename(requestedApparentPath);
              nocache(res);
              res.render('fs/edit/directory', {
                title: `Editing ${dirData.name ?? path.basename(requestedApparentPath)}`,
                perms: { view: req.view, edit: req.edit, download: req.download },
                breadcrumb: genBreadcrumb(requestedApparentPath),
                requestedApparentPath,
                notRoot: requestedApparentPath !== '',
                entryData: dirData,
                filenameTaken: false
              });
            }
          } else {
            nocache(res);
            res.status(403).render('error', { title: 'Error', error: '403 Forbidden' });
          }
        } else if (req.query.hasOwnProperty('download')) {
          if (req.download) {
            if ((await fs.stat(requestedCanonicalPath)).isFile()) {
              res.attachment(path.basename(requestedCanonicalPath));
              const fileReader = fs.createReadStream(requestedCanonicalPath);
              fileReader.pipe(res);
            } else { // send folder compressed
              if (req.query.format === 'gz') {
                res.attachment(`${path.basename(requestedCanonicalPath)}.tar.gz`);
                const tarStream = tar.c({
                  gzip: true,
                  portable: true,
                  noDirRecurse: false,
                  cwd: path.normalize(`${requestedCanonicalPath}/..`)
                }, [path.basename(requestedCanonicalPath)]);
                tarStream.pipe(res);
              } else if (req.query.format === 'xz') {
                res.attachment(`${path.basename(requestedCanonicalPath)}.tar.xz`);
                const xzr = new xz.Compressor();
                const tarStream = tar.c({
                  gzip: false,
                  portable: true,
                  noDirRecurse: false,
                  cwd: path.normalize(`${requestedCanonicalPath}/..`)
                }, [path.basename(requestedCanonicalPath)]);
                tarStream.pipe(xzr).pipe(res);
              } else if (req.query.format === 'zip') {
                res.attachment(`${path.basename(requestedCanonicalPath)}.zip`);
                const zipStream = archiver('zip', {
                  zlib: { level: 6 }
                });
                zipStream.pipe(res);
                zipStream.directory(requestedCanonicalPath, path.basename(requestedCanonicalPath));
                zipStream.finalize();
              } else {
                nocache(res);
                res.status(300).render('fs/download/choices', { title: 'Choose Format', requestedApparentPath });
              }
            }
          } else {
            nocache(res);
            res.status(403).render('error', { title: 'Error', error: '403 Forbidden' }); // don't need to be nice since this is not a page the user should have been able to access.
          }
        } else {
          if (req.view) {
            if ((await fs.stat(requestedCanonicalPath)).isFile()) {
              const fileData: basicEntryData = await new Promise((resolve, reject) => connection.query('SELECT name, descr FROM files WHERE path = ?', [requestedApparentPath], function (err: MysqlError | null, results: basicEntryData[]) { if (err) reject(err); else resolve(results[0]); }));
              // file: basic view with navigation (left right, up (if applicable), and home) and breadcrumb
              const containerData = await fs.readdir(path.normalize(`${requestedCanonicalPath}/..`));
              const links: Links = {
                up: path.normalize(`${requestedApparentPath}/..`) === '.' ? '' : `/${path.normalize(`${requestedApparentPath}/..`)}`,
                first: path.normalize(`${requestedApparentPath}/../${containerData[0]}`),
                last: path.normalize(`${requestedApparentPath}/../${containerData[containerData.length - 1]}`)
              };
              const indexInDir = containerData.findIndex((el: string) => el === path.basename(requestedApparentPath));
              if (indexInDir !== 0) links.previous = path.normalize(`${requestedApparentPath}/../${containerData[indexInDir - 1]}`);
              if (indexInDir !== containerData.length - 1) links.next = path.normalize(`${requestedApparentPath}/../${containerData[indexInDir + 1]}`);
              nocache(res);
              if (isImage(requestedCanonicalPath)) {
                let hash;
                do hash = crypto.randomBytes(16).toString('hex'); while (resourceHashes.has(hash));
                resourceHashes.set(hash, requestedCanonicalPath);
                res.render('fs/view/image', { title: fileData?.name ?? path.basename(requestedCanonicalPath), breadcrumb: genBreadcrumb(requestedApparentPath), links, entryData: fileData ?? {}, tmpLink: `/hres/${hash}`, perms: { view: req.view, edit: req.edit, download: req.download } });
              } else if (isVideo(requestedCanonicalPath)) {
                let hash;
                do hash = crypto.randomBytes(16).toString('hex'); while (resourceHashes.has(hash));
                resourceHashes.set(hash, requestedCanonicalPath);
                res.render('fs/view/video', { title: fileData?.name ?? path.basename(requestedCanonicalPath), breadcrumb: genBreadcrumb(requestedApparentPath), links, entryData: fileData ?? {}, tmpLink: `/hres/${hash}`, perms: { view: req.view, edit: req.edit, download: req.download } });
              } else if (path.parse(requestedCanonicalPath).ext === '.txt') {
                res.render('fs/view/text', { title: fileData?.name ?? path.basename(requestedCanonicalPath), breadcrumb: genBreadcrumb(requestedApparentPath), links, entryData: fileData ?? {}, contentString: await new Promise((resolve, reject) => fs.readFile(requestedCanonicalPath, 'utf8', function (err: Error | null, contents: string) { if (err) reject(err); else resolve(contents); })), perms: { view: req.view, edit: req.edit, download: req.download } });
              } else {
                res.render('fs/view/unrecognized', { title: fileData?.name ?? path.basename(requestedCanonicalPath), breadcrumb: genBreadcrumb(requestedApparentPath), links, entryData: fileData ?? {}, perms: { view: req.view, edit: req.edit, download: req.download } });
              }
            } else {
              const realContentsData: Dirent[] = await promisify(realfs.readdir)(requestedCanonicalPath, { encoding: 'utf8', withFileTypes: true });
              const dirData: limitedEntryData = await new Promise((resolve, reject) => connection.query('SELECT name, descr FROM dirs WHERE path = ?', [requestedApparentPath], function (err: MysqlError | null, results: limitedEntryData[]) { if (err) reject(err); else resolve(results[0]); }));
              let finalContentsData: Array<{ path: string, name: string, isDirectory: boolean }>;
              if (realContentsData.length > 0) {
                const queryLists = realContentsData.reduce((acc: [string[], string[]], el: Dirent) => {
                  //   1 if directory, 0 if file
                  acc[+el.isDirectory()].push(path.join(requestedApparentPath, el.name));
                  return acc;
                }, [[], []]);
                const dbContentsData = ((await new Promise((resolve: (value: limitedEntryData[]) => void, reject: (reason: Error) => void) => connection.query((queryLists[0].length !== 0 ? `SELECT path, name FROM files WHERE path IN (${connection.escape(queryLists[0])})` : '') + (queryLists[0].length !== 0 && queryLists[1].length !== 0 ? ' UNION ALL ' : '') + (queryLists[1].length !== 0 ? `SELECT path, name FROM dirs WHERE path IN (${connection.escape(queryLists[1])})` : ''), function (err: MysqlError | null, results: limitedEntryData[]) { if (err) reject(err); else resolve(results); }))) ?? [])
                  .reduce((acc, el) => {
                    acc.set(el.path, el.name);
                    return acc;
                  }, new Map());
                finalContentsData = realContentsData.map(el => {
                  const dbPath = path.join(requestedApparentPath, el.name);
                  return {
                    path: dbPath,
                    name: dbContentsData.has(dbPath) ? dbContentsData.get(dbPath) : el.name,
                    isDirectory: el.isDirectory()
                  };
                });
              } else {
                finalContentsData = [];
              }
              let links: Links = {};
              let disableHome = false;
              if (requestedApparentPath !== '') {
                const containerData = await fs.readdir(path.normalize(`${requestedCanonicalPath}/..`));
                links = {
                  up: path.normalize(`${requestedApparentPath}/..`) === '.' ? '/' : `/${path.normalize(`${requestedApparentPath}/..`)}`,
                  first: path.normalize(`${requestedApparentPath}/../${containerData[0]}`),
                  last: path.normalize(`${requestedApparentPath}/../${containerData[containerData.length - 1]}`)
                };
                const indexInDir = containerData.findIndex((el: string) => el === path.basename(requestedApparentPath));
                if (indexInDir !== 0) links.previous = path.normalize(`${requestedApparentPath}/../${containerData[indexInDir - 1]}`);
                if (indexInDir !== containerData.length - 1) links.next = path.normalize(`${requestedApparentPath}/../${containerData[indexInDir + 1]}`);
              } else {
                disableHome = true;
              }
              nocache(res);
              res.render('fs/view/directory', { disableHome, title: dirData?.name ?? path.basename(requestedCanonicalPath), breadcrumb: genBreadcrumb(requestedApparentPath), requestedApparentPath, contents: finalContentsData, entryData: dirData ?? {}, links, perms: { view: req.view, edit: req.edit, download: req.download } });
            }
          } else {
            nocache(res);
            res.status(403).render('error', { title: 'Error', error: '403 Forbidden' });
          }
        }
      } else {
        next(); // pass to 404 handler.
      }
    }
  } catch (e) {
    const ecode = Date.now();
    warn(`Internal server error within GET to /portal${req.url} (code ${req.ip}+${ecode}; user '${req.user}'): ${e.stack ? `\n${e.stack}` : `${e.name}: ${e.message}`}`);
    nocache(res);
    res.status(500).send(`We've encountered an internal server error while processing this request. Please try again later, and contact the site owner and mention the error code '${req.ip}+${ecode}'.`);
  }
});
fsRouter.post('/**', async (req: Request, res: Response, next: () => void) => { // we are doing some sort of editing
  const requestedApparentPath = req.path.slice(1);
  const requestedCanonicalPath = path.join(process.cwd(), 'fs', requestedApparentPath);
  try {
    if (req.url.includes('..')) {
      next(); // if someone tries to access files outside of the fs folder with relative paths, we'll just tell them it doesn't exist.
    } else if (req.path !== '/' && req.path.slice(-1) === '/') {
      res.redirect(308, `/portal${req.path === '/' ? '' : '/'}${req.path.slice(0, -1)}`); // remove trailing slash if present and redirect with 308 Permanent Redirect (important to be 308 since we want POSTs to be redirected as-is to the canonical URL).
    } else if (await new Promise((resolve, reject) => { try { fs.exists(requestedCanonicalPath, resolve); } catch (e) { reject(e); } })) { // for now only support metadata editing
      let m: RegExpExecArray | null;
      if (!req.edit) {
        res.status(403).render('error', { title: 'Error', error: '403 Forbidden' });
      } else if (req.body.hasOwnProperty('name') && req.body.hasOwnProperty('descr')) { // edit metadata
        /* eslint-disable curly */
        if ((await fs.stat(requestedCanonicalPath)).isDirectory())
          await new Promise((resolve, reject) => connection.query('IF EXISTS(SELECT * FROM dirs WHERE path = ?) THEN UPDATE dirs SET ? WHERE path = ?; ELSE INSERT INTO dirs (name, descr, path) VALUES (?, ?, ?); END IF', [requestedApparentPath, { name: req.body.name, descr: req.body.descr }, requestedApparentPath, req.body.name, req.body.descr, requestedApparentPath], function (err: MysqlError | null) { if (err) reject(err); else resolve(); }));
        else
          await new Promise((resolve, reject) => connection.query('IF EXISTS(SELECT * FROM files WHERE path = ?) THEN UPDATE files SET ? WHERE path = ?; ELSE INSERT INTO files (name, descr, path) VALUES (?, ?, ?); END IF', [requestedApparentPath, { name: req.body.name, descr: req.body.descr }, requestedApparentPath, req.body.name, req.body.descr, requestedApparentPath], function (err: MysqlError | null) { if (err) reject(err); else resolve(); }));
        /* eslint-enable curly */
        res.redirect(`/portal/${requestedApparentPath}`);
      } else if (req.body.hasOwnProperty('newFilename') || req.body.hasOwnProperty('newDirname')) {
        const fileType = (await fs.stat(requestedCanonicalPath)).isDirectory() ? 'dir' : 'file';
        if (req.body.hasOwnProperty('newFilename') && fileType === 'file') { // rename file and redirect to new URL.
          if (await new Promise((resolve, reject) => { try { fs.exists(path.join(path.dirname(requestedCanonicalPath), req.body.newFilename), resolve); } catch (err) { reject(err); } })) {
            const fileData: basicEntryData = await new Promise((resolve, reject) => connection.query('SELECT name, descr FROM files WHERE path = ?', [requestedApparentPath], function (err: MysqlError | null, results: basicEntryData[]) { if (err) reject(err); else resolve(results[0] ?? {}); }));
            fileData.filename = path.basename(requestedApparentPath);
            nocache(res);
            res.render('fs/edit/file', {
              title: `Editing ${fileData.name ?? path.basename(requestedApparentPath)}`,
              perms: { view: req.view, edit: req.edit, download: req.download },
              breadcrumb: genBreadcrumb(requestedApparentPath),
              requestedApparentPath,
              entryData: fileData,
              filenameTaken: true
            });
          } else {
            await promisify(fs.rename)(requestedCanonicalPath, path.join(path.dirname(requestedCanonicalPath), req.body.newFilename));
            try {
              await new Promise((resolve, reject) => connection.query('UPDATE files SET path = ? WHERE path = ?', [path.join(path.dirname(requestedCanonicalPath), req.body.newFilename), requestedCanonicalPath], function (err) { if (err) reject(err); else resolve(); }));
              res.redirect(301, path.normalize(path.join('/portal', path.dirname(requestedApparentPath), req.body.newFilename)));
            } catch (err) {
              await promisify(fs.rename)(path.join(path.dirname(requestedCanonicalPath), req.body.newFilename), requestedCanonicalPath); // atomicity
              throw err;
            }
          }
        } else if (req.body.hasOwnProperty('newDirname') && fileType === 'dir' && requestedApparentPath !== '/') {
          // rename directory and redirect to new URL.
          if (await new Promise((resolve, reject) => { try { fs.exists(path.join(path.dirname(requestedCanonicalPath), req.body.newDirname), resolve); } catch (e) { reject(e); } })) {
            const dirData: basicEntryData = await new Promise((resolve, reject) => connection.query('SELECT name, descr FROM dirs WHERE path = ?', [requestedApparentPath], function (err: MysqlError | null, results: basicEntryData[]) { if (err) reject(err); else resolve(results[0] ?? {}); }));
            dirData.filename = path.basename(requestedApparentPath);
            nocache(res);
            res.render('fs/edit/directory', {
              title: `Editing ${dirData.name ?? path.basename(requestedApparentPath)}`,
              perms: { view: req.view, edit: req.edit, download: req.download },
              breadcrumb: genBreadcrumb(requestedApparentPath),
              requestedApparentPath,
              notRoot: requestedApparentPath !== '',
              entryData: dirData,
              dirnameTaken: true,
              filenameTaken: false
            });
          } else {
            await promisify(fs.rename)(requestedCanonicalPath, path.join(path.dirname(requestedCanonicalPath), req.body.newDirname));
            try {
              await new Promise((resolve, reject) =>
                connection.query(
                  `START TRANSACTION; UPDATE files SET path = REGEXP_REPLACE(path, ${connection.escape(`^${requestedApparentPath}`)}, ${connection.escape(path.normalize(path.join(path.dirname(requestedApparentPath), req.body.newDirname)))}) WHERE path RLIKE ${connection.escape(`^${requestedApparentPath}`)}; UPDATE dirs SET path = REGEXP_REPLACE(path, ${connection.escape(`^${requestedApparentPath}`)}, ${connection.escape(path.normalize(path.join(path.dirname(requestedApparentPath), req.body.newDirname)))}) WHERE path RLIKE ${connection.escape(`^${requestedApparentPath}`)}; COMMIT`,
                  (err: MysqlError) => { if (err) reject(err); else resolve(); }
                )
              );
              nocache(res);
              res.redirect(301, path.normalize(path.join('/portal', path.dirname(requestedApparentPath), req.body.newDirname)));
            } catch (err) {
              await promisify(fs.rename)(path.join(path.dirname(requestedCanonicalPath), req.body.newDirname), requestedCanonicalPath);
              throw err;
            }
          }
        } else {
          nocache(res);
          res.status(400).render('error', { title: 'Error', error: '400 Bad Request' });
        }
      } else if (req.body.hasOwnProperty('delete') && req.body.delete === 'yesactuallydeletethis') { // delete
        if ((await fs.stat(requestedCanonicalPath)).isDirectory()) {
          if (requestedApparentPath === '/') {
            res.status(400).render('error', { title: 'Error', error: '400 Bad Request' }); // preserve root
          } else {
            await promisify(realfs.rmdir)(requestedCanonicalPath, { recursive: true });
            await new Promise((resolve, reject) => connection.query('DELETE FROM dirs WHERE path = ?', [requestedApparentPath], function (err: MysqlError | null) { if (err) reject(err); else resolve(); }));
            res.redirect(`/portal${path.normalize(`${requestedApparentPath}/..`) === '.' ? '' : `/${path.dirname(requestedApparentPath)}`}`);
          }
        } else {
          await promisify(fs.unlink)(requestedCanonicalPath);
          await new Promise((resolve, reject) => connection.query('DELETE FROM files WHERE path = ?', [requestedApparentPath], function (err: MysqlError | null) { if (err) reject(err); else resolve(); }));
          res.redirect(`/portal/${path.dirname(requestedApparentPath)}`);
        }
      } else if (req.body.hasOwnProperty('empty') && req.body.empty === 'yesactuallyemptythis') {
        if ((await fs.stat(requestedCanonicalPath)).isDirectory()) {
          await new Promise((resolve, reject) => connection.query('DELETE FROM files WHERE path RLIKE ?; DELETE FROM dirs WHERE path RLIKE ?', [`^${requestedApparentPath}/`, `^${requestedApparentPath}/`], (err: MysqlError | null) => { if (err) reject(err); else resolve(); }));
          await fs.emptyDir(requestedCanonicalPath);
          const dirData: basicEntryData = await new Promise((resolve, reject) => connection.query('SELECT name, descr FROM dirs WHERE path = ?', [requestedApparentPath], function (err: MysqlError | null, results: basicEntryData[]) { if (err) reject(err); else resolve(results[0] ?? {}); }));
          dirData.filename = path.basename(requestedApparentPath);
          nocache(res);
          res.render('fs/edit/directory', {
            title: `Editing ${dirData.name ?? path.basename(requestedApparentPath)}`,
            perms: { view: req.view, edit: req.edit, download: req.download },
            breadcrumb: genBreadcrumb(requestedApparentPath),
            requestedApparentPath,
            notRoot: requestedApparentPath !== '',
            entryData: dirData,
            dirnameTaken: true,
            filenameTaken: false
          });
        } else {
          nocache(res);
          res.status(400).render('error', { title: 'Error', error: '400 Bad Request' });
        }
      } else if (req.body.hasOwnProperty('createDirname') && (!req.body.hasOwnProperty('includeDirMetadata') || (req.body.includeDirMetadata === 'yes' && req.body.hasOwnProperty('metadataDirName') && req.body.hasOwnProperty('metadataDirDescr')))) {
        if (await new Promise((resolve, reject) => { try { fs.exists(path.join(requestedCanonicalPath, req.body.createDirname), resolve); } catch (err) { reject(err); } })) {
          const dirData: basicEntryData = await new Promise((resolve, reject) => connection.query('SELECT name, descr FROM dirs WHERE path = ?', [requestedApparentPath], function (err: MysqlError | null, results: basicEntryData[]) { if (err) reject(err); else resolve(results[0] ?? {}); }));
          dirData.filename = path.basename(requestedApparentPath);
          nocache(res);
          res.render('fs/edit/directory', {
            title: `Editing ${dirData.name ?? path.basename(requestedApparentPath)}`,
            perms: { view: req.view, edit: req.edit, download: req.download },
            breadcrumb: genBreadcrumb(requestedApparentPath),
            requestedApparentPath,
            notRoot: requestedApparentPath !== '',
            entryData: dirData,
            createDirnameTaken: true
          });
        } else {
          await promisify(fs.mkdir)(path.join(requestedCanonicalPath, req.body.createDirname));
          if (req.body.hasOwnProperty('includeDirMetadata')) {
            await new Promise((resolve, reject) => connection.query('INSERT INTO dirs (path, name, descr) VALUES (?, ?, ?)', [path.join(requestedApparentPath, req.body.createDirname), req.body.metadataDirName, req.body.metadataDirDescr]));
          }
          res.redirect(`/portal/${path.join(requestedApparentPath, req.body.createDirname)}`);
        }
      } else if (req.headers['content-type'] && (m = (/^multipart\/.+?(?:; boundary=(?:(?:"(.+)")|(?:([^\s]+))))$/i).exec(req.headers['content-type']))) {
        let tempFileName: string;
        do tempFileName = crypto.randomBytes(16).toString('hex'); while (await new Promise((resolve, reject) => {
          try {
            fs.exists(path.join(process.cwd(), 'tmp', tempFileName), function (exists) { resolve(exists); });
          } catch (err) {
            reject(err);
          }
        }));

        const fstream = fs.createWriteStream(path.join(process.cwd(), 'tmp', tempFileName), { flags: 'w' });
        const requestProps: RequestProps = {
          received: false,
          formData: {
            filename: ''
          },
          invalid: false
        };
        const isFormDataIndex = (key: string): key is keyof RequestProps['formData'] => {
          return ['filename', 'includeMetadata', 'metadataName', 'metadataDescr'].includes(key);
        };
        const data = new multiparty.Form();
        data.on('error', (err: Error) => { throw err; });
        data.on('part', function (part: multiparty.Part) {
          if (part.filename) {
            if (!requestProps.received) {
              requestProps.received = true;
              requestProps.formData.defaultFilename = part.filename;
              part.pipe(fstream);
            } else { // sent too many files; bad request
              requestProps.invalid = true;
            }
          } else if (part.name) {
            if (isFormDataIndex(part.name)) {
              part.on('readable', function () {
                const data = part.read();
                // @ts-expect-error on next line - We check that the string used to index requestProps.formData is one of the allowed keys three lines above.
                if (data !== null) requestProps.formData[part.name] = data.toString('utf-8');
              });
            } else { // some other parameter; bad request
              requestProps.invalid = true;
            }
          }
        });
        data.on('close', async function () {
          if (requestProps.invalid) {
            res.status(400).render('error', { title: 'Error', error: '400 Bad Request' });
          } else {
            const fileType = (await fs.stat(requestedCanonicalPath)).isDirectory() ? 'dir' : 'file';
            if (Object.keys(requestProps.formData).length === 0 && fileType === 'file') { // replace file
              const parsedCanonical = path.parse(requestedCanonicalPath);
              const parsedApparent = path.parse(requestedApparentPath);
              const correctedExtension: string = await new Promise((resolve, reject) => childprocess.exec(`file -bp --mime-type ${requestedCanonicalPath}`, function (err: childprocess.ExecException | null, stdout: string, stderr: string) {
                if (err) reject(err); else {
                  stdout = stdout.trim();
                  switch (stdout) {
                    case 'inode/x-empty':
                    case 'application/octet-stream':
                      resolve(parsedApparent.ext); // act like it's whatever they say it is if it's empty or if it can't be identified
                      break;
                    default:
                      (ext => resolve(ext === false ? '' : ext))(mime.extension(stdout));
                      break;
                  }
                }
              }));
              await promisify(fs.unlink)(requestedCanonicalPath);
              await promisify(fs.rename)(path.join(process.cwd(), 'tmp', tempFileName), path.join(parsedCanonical.dir, parsedCanonical.name + correctedExtension));
              await new Promise((resolve, reject) => connection.query('IF EXISTS(SELECT * FROM files WHERE path = ?) THEN UPDATE files SET path = ? WHERE path = ?; END IF', [requestedApparentPath, path.join(parsedApparent.dir, parsedApparent.name + correctedExtension), requestedApparentPath], function (err: MysqlError | null) { if (err) reject(err); else resolve(); }));
              res.redirect(`/portal/${path.join(parsedApparent.dir, parsedApparent.name + correctedExtension)}`);
            } else if (fileType === 'dir' && requestProps.formData.hasOwnProperty('defaultFilename') && requestProps.formData.defaultFilename) { // add file to directory
              if (!requestProps.formData.filename) requestProps.formData.filename = requestProps.formData.defaultFilename;
              if (await new Promise((resolve, reject) => { try { fs.exists(path.join(requestedApparentPath, requestProps.formData.filename), resolve); } catch (err) { reject(err); } })) {
                await promisify(fs.unlink)(path.join(process.cwd(), 'tmp', tempFileName));
                const dirData: basicEntryData = await new Promise((resolve, reject) => connection.query('SELECT name, descr FROM dirs WHERE path = ?', [requestedApparentPath], function (err: MysqlError | null, results: basicEntryData[]) { if (err) reject(err); else resolve(results[0] ?? {}); }));
                dirData.filename = path.basename(requestedApparentPath);
                nocache(res);
                res.render('fs/edit/directory', {
                  title: `Editing ${dirData.name ?? path.basename(requestedApparentPath)}`,
                  perms: { view: req.view, edit: req.edit, download: req.download },
                  breadcrumb: genBreadcrumb(requestedApparentPath),
                  requestedApparentPath,
                  entryData: dirData,
                  filenameTaken: true,
                  notRoot: requestedApparentPath !== ''
                });
              } else {
                if (!requestProps.formData.filename) requestProps.formData.filename = requestProps.formData.defaultFilename;
                await promisify(fs.rename)(path.join(process.cwd(), 'tmp', tempFileName), path.join(requestedCanonicalPath, requestProps.formData.filename));
                if (requestProps.formData.hasOwnProperty('includeMetadata') && requestProps.formData.includeMetadata === 'yes') {
                  if (requestProps.formData.metadataName && requestProps.formData.metadataDescr) {
                    await new Promise((resolve, reject) => connection.query('INSERT INTO files (path, name, descr) VALUES (?, ?, ?)', [path.join(requestedApparentPath, requestProps.formData.filename), requestProps.formData.metadataName, requestProps.formData.metadataDescr], function (err) { if (err) reject(err); else resolve(); }));
                  } else {
                    nocache(res);
                    res.status(400).render('error', { title: 'Error', error: '400 Bad Request' });
                  }
                }
                const dirData: basicEntryData = await new Promise((resolve, reject) => connection.query('SELECT name, descr FROM dirs WHERE path = ?', [requestedApparentPath], function (err: MysqlError | null, results: basicEntryData[]) { if (err) reject(err); else resolve(results[0] ?? {}); }));
                dirData.filename = path.basename(requestedApparentPath);
                nocache(res);
                res.render('fs/edit/directory', {
                  title: `Editing ${dirData.name ?? path.basename(requestedApparentPath)}`,
                  perms: { view: req.view, edit: req.edit, download: req.download },
                  breadcrumb: genBreadcrumb(requestedApparentPath),
                  requestedApparentPath,
                  notRoot: requestedApparentPath !== '',
                  entryData: dirData,
                  filenameTaken: false,
                  actionNotification: `Successfully added ${requestProps.formData.filename}. View it ${'here'.link(path.join('/portal', requestedApparentPath, requestProps.formData.filename))}.`
                });
              }
            } else { // wrong combination of request and entry type in filesystem; bad request
              nocache(res);
              res.status(400).render('error', { title: 'Error', error: '400 Bad Request' });
            }
          }
        });
        data.parse(req);
      } else {
        nocache(res);
        res.status(400).render('error', { title: 'Error', error: '400 Bad Request' });
      }
    } else {
      next();
    }
  } catch (e) {
    const ecode = Date.now();
    warn(`Internal server error within POST to /portal${req.url} (code ${req.ip}+${ecode}; user '${req.user}'):${e.stack ? `\n${e.stack}` : ` ${e.name}: ${e.message}`}`);
    nocache(res);
    res.status(500).send(`We've encountered an internal server error while processing this request. Please try again later, and contact the site owner and mention the error code '${req.ip}+${ecode}'.`);
  }
});

app.all('/**', (req: Request, res: Response) => void res.status(404).render('error', {
  title: 'Error',
  error: '404 Not Found'
})); // if there is no registered handler don't send the default message; instead send a 404 with our error page.

// const https = require('https');
// const secureServer = https.createServer({
//   key: fs.readFileSync('./server.key'),
//   cert: fs.readFileSync('./server.cert')
// }, app).listen(3443);
const server = app.listen(3000);

const cleanExit = () => {
  for (const file of fs.readdirSync(path.join(process.cwd(), 'tmp'))) {
    fs.unlinkSync(path.join(process.cwd(), 'tmp', file));
  }
  log('Stopping Express servers...');
  // secureServer.close(err => { if (err) error(`While stopping HTTPS Express server: ${err.stack ? `\n${err.stack}` : `${err.name}: ${err.message}`}`); else log('Stopped HTTPS Express server.'); });
  server.close((err: Error | undefined) => { if (err) error(`While stopping HTTP Express server: ${err.stack ? `\n${err.stack}` : `${err.name}: ${err.message}`}`); else log('Stopped HTTP Express server.'); });
  fs.writeSync(logfile, `Stop server at ${new Date().toLocaleString()}\n---------------\n`);
  fs.closeSync(logfile);
  if (!process.env.nolog) {
    const lastlogStream = fs.createReadStream(path.join(process.cwd(), 'lastlog'));
    const logStream = fs.createWriteStream(path.join(process.cwd(), 'log'), {
      flags: 'a'
    });
    lastlogStream.pipe(logStream);
    lastlogStream.unpipe(logStream);
  }
};

process.on('SIGINT', () => {
  info('Got SIGINT, cleaning up.', { overwrite: true });
  cleanExit();
});

process.on('uncaughtException', err => {
  info('Exiting with uncaught exception; information follows.');
  log('Stopping Express servers...');
  // secureServer.close(err => { if (err) error(`While stopping HTTPS Express server: ${err.stack ? `\n${err.stack}` : `${err.name}: ${err.message}`}`); else log('Stopped HTTPS Express server.'); });
  server.close((err: Error | undefined) => { if (err) error(`While stopping HTTP Express server: ${err.stack ? `\n${err.stack}` : `${err.name}: ${err.message}`}`); else log('Stopped HTTP Express server.'); });
  error(err.stack ? `\n${err.stack}` : `${err.name}: ${err.message}`);
  fs.writeSync(logfile, `Stop server at ${new Date().toLocaleString()}\n---------------\n`);
  fs.closeSync(logfile);
  if (!process.env.nolog) {
    const lastlogStream = fs.createReadStream(path.join(process.cwd(), 'lastlog'));
    const logStream = fs.createWriteStream(path.join(process.cwd(), 'log'), {
      flags: 'a'
    });
    lastlogStream.pipe(logStream);
    lastlogStream.unpipe(logStream);
  }
  process.exit(1);
});

module.exports = { app, server, cleanExit };
