const { JWT_SECRET } = require('../secrets');
const jwt = require('jsonwebtoken');

function generateToken(user){
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  const options = {
    expiresIn: '30s'
  }

  return jwt.sign(payload, JWT_SECRET, options);
}

module.exports = {
  generateToken
}