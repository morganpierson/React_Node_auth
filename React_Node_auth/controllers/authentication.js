const User = require('../models/user');
const jwt = require('jwt-simple');
const config = require('../config');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signup = function(req, res, next) {
  //see if user with given email exists
  const email = req.body.email;
  const password = req.body.password;
  User.findOne({ email: email }, (err, user) => {
    if(err) {
      return next(err);
    }

    if(!email || !password) {
      return res.status(422).send({ error: 'email and password must be provided' })
    }
    if(user) { 
      return res.status(422).send({ error: 'email already in use' });
    } else {
      const user = new User({
        email: email,
        password: password
      });

      user.save(function(err) {
        if(err) return next(err);

        res.json({ token: tokenForUser(user) });
      });
    }
  })

    //if yes, return error
    //else create and save user record & respond to request indicating user was created
}

exports.signin = function (req, res, next) {
  //user has already had their email and password authorized 
  //just need to give them a token
  res.send({ token: tokenForUser(req.user) })
}