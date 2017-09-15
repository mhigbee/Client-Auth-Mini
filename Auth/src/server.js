const bodyParser = require('body-parser');
const express = require('express');
const session = require('express-session');
const User = require('./user.js');
const bcrypt = require('bcrypt');
const cors = require('cors');

const STATUS_USER_ERROR = 422;
const BCRYPT_COST = 11;

const server = express();
// to enable parsing of json bodies for post requests
server.use(bodyParser.json());
server.use(session({
  secret: 'e5SPiqsEtjexkTj3Xqovsjzq8ovjfgVDFMfUzSmJO21dtXs4re',
  resave: true,
  saveUninitialized: true
}));

const corsOptions = {
  "origin": "http://localhost:3000",
  "credentials": true
};
server.use(cors(corsOptions));

/* Sends the given err, a string or an object, to the client. Sets the status
 * code appropriately. */


const sendUserError = (err, res) => {
  res.status(STATUS_USER_ERROR);
  if (err && err.message) {
    res.json({ message: err.message, stack: err.stack });
  } else {
    res.json({ error: err });
  }
};

const ensureLogin = (req, res, next) => {
  const { username } = req.session;
  if (!username) {
    sendUserError('must be logged in', res);
    return;
  }

  User.findOne({ username }, (err, user) => {
    if (err) {
      sendUserError(err, res);
      return;
    }

    if (!user) {
      sendUserError('must be logged in', res);
      return;
    }

    req.user = user;
    next();
  });
};

server.post('/users', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    sendUserError('Please provide a username and password', res);
    return;
  }
  bcrypt.hash(password, BCRYPT_COST, (err, hash) => {
    if (err) return sendUserError('Error saving password', res);
    const newUser = new User({ username, passwordHash: hash });
    newUser.save((userErr, user) => {
      if (userErr) return sendUserError('Enter a unique username', res);
      res.json(user);
    });
  });
});

server.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    sendUserError('Please provide a username and password', res);
    return;
  }
  User.findOne({ username }, (err, user) => {
    if (user === null) return sendUserError('No User Found', res);
    bcrypt.compare(password, user.passwordHash, (error, bcryptRes) => {
      if (error) return sendUserError('Error wrong password', res);
      req.session.username = user.username;
      res.json({ success: bcryptRes });
    });
  });
});

server.post('/logout', (req, res) =>{
  const { username } = req.body;
  if(!req.session.username) {
    sendUserError('User already logged out', res);
    return;
  }
  if (req.session.username === username) {
    delete req.session.username
    res.json({message: 'Successfully logged out'});
  }
});

const restrictAccess = (req, res, next) => {
  const path = req.path;
  if (/restricted/.test(path)) {
    if (!req.session.username) {
      sendUserError('Must be logged in to access', res);
      return;
    }
  }
  next();
};

server.use(restrictAccess);

// TODO: add local middleware to this route to ensure the user is logged in
server.get('/me', ensureLogin, (req, res) => {
  // Do NOT modify this route handler in any way.
  res.json(req.user);
});

module.exports = { server };
