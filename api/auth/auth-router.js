const bcrypt = require('bcryptjs');
const User = require('../users/users-model');
const jwt = require('jsonwebtoken');
const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!

const { generateToken } = require('../utils');

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  let user = req.body;
  
  const rounds = process.env.BCRYPT_ROUNDS || 8;
  const hash = bcrypt.hashSync(user.password, rounds);

  user.password = hash;
  user.role_name = req.role_name;

  try {
    const saved = await User.add(user);
    res.status(201).json(saved);
  } catch(err) {
    next(err);
  }

});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */

  const { username, password } = req.body;

  if(req.user && bcrypt.compareSync(password, req.user.password)){
    const token = generateToken(req.user);
    res.status(200).json({
      message: `${username} is back!`,
      token
    })
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }

});

router.use((err, req, res, next) => { //eslint-disable-line
  res.status(err.status || 500).json({
    message: err.message,
    stack: err.stack
  })
});

module.exports = router;
