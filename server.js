/* Author:      Alexia Cobb (alexiacobb@my.unt.edu)
 * EUID:		    asc0223
 * Assignment:  Project 2 - Extending the JWKS Server
 * Class:       CSCE 3550
 * Instructor:  Dr. Hochstetler
 * Due Date:    29 October 2023
*/

// used base files provided by Dr. Hochstetler
// lines added for completion of project 2 are commented

const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');

const app = express();
const port = 8080;

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;

async function generateKeyPairs() {
  keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
}

function generateToken() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: keyPair.kid
    }
  };

  token = jwt.sign(payload, keyPair.toPEM(true), options);
}

function generateExpiredJWT() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000) - 30000,
    exp: Math.floor(Date.now() / 1000) - 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: expiredKeyPair.kid
    }
  };

  expiredToken = jwt.sign(payload, expiredKeyPair.toPEM(true), options);
}

// database operations
function db() {
  const sqlite3 = require('sqlite3').verbose();
  let db = new sqlite3.Database('./totally_not_my_privateKeys.db'); // create database file
  db.run('CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT,key BLOB NOT NULL,exp INTEGER NOT NULL)'); // create table
  db.run('INSERT INTO keys(key, exp) VALUES(?, ?)', [keyPair.toPEM(true), Math.floor(Date.now() / 1000) + 3600]); // insert valid private key into database
  db.run('INSERT INTO keys(key, exp) VALUES(?, ?)', [expiredKeyPair.toPEM(true), Math.floor(Date.now() / 1000) - 3600]); // insert expired private key into database
}

app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Middleware to ensure only GET requests are allowed for /jwks
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.get('/.well-known/jwks.json', (req, res) => {
  const validKeys = [keyPair].filter(key => !key.expired);
  res.setHeader('Content-Type', 'application/json');
  res.json({ keys: validKeys.map(key => key.toJSON()) });
});

app.post('/auth', (req, res) => {

  if (req.query.expired === 'true'){
    return res.send(expiredToken);
  }
  res.send(token);
});

generateKeyPairs().then(() => {
  generateToken()
  generateExpiredJWT()
  db() // perform database operations
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
  module.exports = app;
});