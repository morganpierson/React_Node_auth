const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

//create local strategy
const localOptions = { usernameField: 'email' };
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
  //verify email and password, call done with the user if it is the correct email and password
  User.findOne({ email: email }, (err, user) => {
    if(err) {
      return done(err);
    };
    if(!user) {
      return done(null, false, { error: 'Incorrect email/password'})
    } 
    user.comparePassword(password, (err, isMatch) => {
      if(err) {
        return done(err);
      } if(!isMatch) {
        return done(null, false);
      } else {
        return done(null, user);
      }
    })
  //else call done with false
  });
})
//setup options for jwt strategy
const jwtOptions = { 
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
}

//create jwt strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  //see if the user.id in the payload exists in our database
  //if so call done with that user
  //else call done without user object 
  User.findById(payload.sub, (err, user) => {
    if(err) { 
      return  done(err, false) 
    }; 
    if(user) {
      done(null, user)
    } else {
      done(null, false)
    }
  })
})

//tell passport to use this strategy
passport.use(jwtLogin)
passport.use(localLogin)