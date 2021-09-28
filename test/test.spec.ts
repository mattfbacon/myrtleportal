import { expect } from 'chai';
import request = require('supertest');
import fs = require('fs');
import path = require('path');
import { promisify } from 'util';

const { app, cleanExit } = require('../server');
const loggedInUser = request.agent(app);
loggedInUser.post('/login').send({
  username: 'testuser',
  password: 'password'
});

const pick = (number: number) => {
  return {
    from: function<T> (array: Array<T>): Array<T> {
      if (array.length < number) {
        throw new RangeError("Number of element to pick must be greater than the array's length");
      } else if (array.length === number) return array; else {
        const ret = [];
        for (let i = 0; i < number; i++) {
          ret.push(array.splice(Math.floor(Math.random() * array.length), 1)[0]);
        }
        return ret;
      }
    }
  };
};

describe('Requests:', async function () {
  describe('GET /res/...:', async function () {
    describe('in the style directory', function () {
      describe('that exist', function () {
        it('should give a 200 response.', async function () {
          const resourceToGet = (await promisify(fs.readdir)('res/style')).find(el => path.extname(el) === '.css');
          await new Promise((resolve, reject) => request(app).get(path.join('/res/style', resourceToGet)).expect(200).end(function (err) {
            if (err) reject(err); else resolve();
          }));
        });
        it('should give the requested resource in response.', async function () {
          const resourceToGet = (await promisify(fs.readdir)('res/style')).find(el => path.extname(el) === '.css');
          const fileContents = await promisify(fs.readFile)(path.join('res/style', resourceToGet), { encoding: 'utf8' });
          await new Promise((resolve, reject) => request(app).get(path.join('/res/style', resourceToGet)).expect(fileContents).end(function (err) {
            if (err) reject(err); else resolve();
          }));
        });
      });
      describe('that are intentionally hidden (LESS files)', function () {
        it('should give a 404.', async function () {
          const resourceToGet = (await promisify(fs.readdir)('res/style')).find(el => path.extname(el) === '.less');
          await new Promise((resolve, reject) => request(app).get(path.join('/res/style', resourceToGet)).expect(404).end(function (err) {
            if (err) reject(err); else resolve();
          }));
        });
      });
      describe("that don't exist", function () {
        it('should give a 404.', async function () {
          await new Promise((resolve, reject) => request(app).get('/res/style/thiswillneverexist.css').expect(404).end(function (err) {
            if (err) reject(err); else resolve();
          }));
        });
      });
    });
    describe('in the scripts directory', function () {
      describe('that exist', function () {
        it('should give a 200 response.', async function () {
          const resourceToGet = (await promisify(fs.readdir)('res/js')).find(el => path.extname(el) === '.js');
          await new Promise((resolve, reject) => request(app).get(path.join('/res/js', resourceToGet)).expect(200).end(function (err) {
            if (err) reject(err); else resolve();
          }));
        });
        it('should give the requested resource in response.', async function () {
          const resourceToGet = (await promisify(fs.readdir)('res/js')).find(el => path.extname(el) === '.js');
          const fileContents = await promisify(fs.readFile)(path.join('res/js', resourceToGet), { encoding: 'utf8' });
          await new Promise((resolve, reject) => request(app).get(path.join('/res/js', resourceToGet)).expect(fileContents).end(function (err) {
            if (err) reject(err); else resolve();
          }));
        });
      });
      describe('that are intentionally hidden (.eslintrc)', function () {
        it('should give a 404.', async function () {
          await new Promise((resolve, reject) => request(app).get('/res/js/.eslintrc').expect(404).end(function (err) {
            if (err) reject(err); else resolve();
          }));
        });
      });
      describe("that don't exist", function () {
        it('should give a 404.', async function () {
          await new Promise((resolve, reject) => request(app).get('/res/js/thiswillneverexist.js').expect(404).end(function (err) {
            if (err) reject(err); else resolve();
          }));
        });
      });
    });
    const otherExistingFolder = (await promisify(fs.readdir)('res')).find(el => !(['js', 'style'].includes(el)));
    if (otherExistingFolder !== null) {
      describe('in other existing folders', async function () {
        const folderContents = (await promisify(fs.readdir)(path.join('res', otherExistingFolder)));
        if (folderContents.length !== 0) {
          describe('that exist', function () {
            it('should give a 200 response.', async function () {
              await new Promise((resolve, reject) => request(app).get(path.join('/res', otherExistingFolder, folderContents[0])).expect(200).end(function (err) {
                if (err) reject(err); else resolve();
              }));
            });
            it('should give the requested resource in response.', async function () {
              const fileContents = await promisify(fs.readFile)(path.join('res', otherExistingFolder, folderContents[0]), { encoding: 'utf8' });
              await new Promise((resolve, reject) => request(app).get(path.join('/res', otherExistingFolder, folderContents[0])).expect(fileContents).end(function (err) {
                if (err) reject(err); else resolve();
              }));
            });
          });
        }
        describe("that don't exist", function () {
          it('should give a 404.', async function () {
            await new Promise((resolve, reject) => request(app).get(path.join('/res', otherExistingFolder, 'thiswillneverexist.abcdef')).expect(404).end(function (err) {
              if (err) reject(err); else resolve();
            }));
          });
        });
      });
    }
    describe("in other folders that don't exist", function () {
      it('should give a 404.', async function () {
        await new Promise((resolve, reject) => request(app).get('/res/foo/bar.png').expect(404).end(function (err) {
          if (err) reject(err); else resolve();
        }));
      });
    });
    describe('that are for the folders themselves', function () {
      it('should give a 404.', async function () {
        await new Promise((resolve, reject) => request(app).get('/res/style').expect(404).end(function (err) {
          if (err) reject(err); else resolve();
        }));
      });
    });
    describe('that are for the /res folder itself', function () {
      it('should give a 404.', async function () {
        await new Promise((resolve, reject) => request(app).get('/res').expect(404).end(function (err) {
          if (err) reject(err); else resolve();
        }));
      });
    });
  });
  describe('<!GET> /res/...:', function () {
    it('should give 405 Method Not Allowed.', async function () {
      const resourceToGet = (await promisify(fs.readdir)('res/style')).find(el => path.extname(el) === '.css');
      await new Promise((resolve, reject) => request(app).post(path.join('/res/style/', resourceToGet)).expect(405, function (err) {
        if (err) reject(err); else resolve();
      }));
    });
  });
  describe('GET /:', function () {
    describe('when not logged in', function () {
      it('should be fulfilled.', async function () {
        await new Promise((resolve, reject) => request(app).get('/').expect(200).end(function (err) {
          if (err) reject(err); else resolve();
        }));
      });
    });
    describe('when logged in', function () {
      it('should redirect to the welcome page.', async function () {
        await new Promise((resolve, reject) => loggedInUser.get('/').expect(function (res) {
          expect(res.header).to.have.property('Location').that.equals('/welcome');
        }, function (err) {
          if (err) reject(err); else resolve();
        }));
      });
    });
  });
  describe('<!GET> /:', function () {
    it('should give 405 Method Not Allowed.', async function () {
      for (const i of pick(3).from(['post', 'put', 'delete', 'patch'])) {
        await new Promise((resolve, reject) => request(app)[i]('/').expect(405, function (err) {
          if (err) reject(err); else resolve();
        }));
      }
    });
  });
  describe('GET /login:', function () {
    describe('when not logged in', function () {
      it('should send the page without a "You are already logged in" message.', async function () {
        await new Promise((resolve, reject) => request(app).get('/login').expect(200).expect(function (res) {
          expect(res.body.slice(res.body.indexOf('<body>'))).to.not.include('already-logged-in');
        }, function (err) {
          if (err) reject(err); else resolve();
        }));
      });
    });
    describe('when logged in', function () {
      it('should send the page with a "You are already logged in" message.', async function () {
        await new Promise((resolve, reject) => loggedInUser.get('/login').expect(200).expect(function (res) {
          expect(res.body.slice(res.body.indexOf('<body>'))).to.include('already-logged-in');
        }, function (err) {
          if (err) reject(err); else resolve();
        }));
      });
    });
  });
  describe('POST /login:', function () {
    describe('when not logged in', function () {
      it('should log the user in and give them an auth token, then redirect them to the welcome page.', async function () {
        let loginPostUser = request.agent(app);
        await new Promise((resolve, reject) => loginPostUser
          .post('/login')
          .send({
            username: 'testuser',
            password: 'password'
          }).expect(302)
          .expect('set-cookie', /token=.+; Path=\//)
          .expect('location', '/welcome')
          .end(function (err) {
            if (err) reject(err); else resolve();
          })
        );
        loginPostUser = null;
      });
    });
    describe('when logged in', function () {
      it('should replace the session by giving them another auth token, then redirect them to the welcome page.', async function () {
        let loginPostUser = request.agent(app);
        await new Promise((resolve, reject) => loginPostUser
          .post('/login')
          .send({
            username: 'testuser',
            password: 'password'
          }).expect(302)
          .expect('set-cookie', /token=.+; Path=\//)
          .expect('location', '/welcome')
          .end(function (err) {
            if (err) reject(err); else resolve();
          })
        );
        loginPostUser = null;
      });
    });
  });
  describe('<!GET, POST> /login:', function () {
    it('should give 405 Method Not Allowed.', async function () {
      for (const i of pick(3).from(['put', 'delete', 'patch'])) {
        await new Promise((resolve, reject) => request(app)[i]('/login').expect(405, function (err) {
          if (err) reject(err); else resolve();
        }));
      }
    });
  });
});

after(function () {
  cleanExit();
  setTimeout(() => process.exit(0), 1000);
});
