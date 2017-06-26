const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');
//Define user model
const userSchema = new Schema({
  email: {
   type: String,
   unique: true,
   lowercase: true
  },
  password: String
})

//On save hook, encrypt password
//Before saving a user model, run this function
userSchema.pre('save', function(next) {
  //get access to the user model
  const user = this;

  //generate a salt, then run callback
  bcrypt.genSalt(10, (err, salt) => {
    if(err) return next(err);

    //hash (encrypt) password using the salt
    bcrypt.hash(user.password, salt, null, (err, hash) => {
      if(err) return next(err);

      //overwrite plain text password with encrypted password
      user.password = hash;
      next();
    })
  })
});

//compares stored user password with attempted signin (candidatePassword) password
userSchema.methods.comparePassword = function(candidatePassword, callback) {
  bcrypt.compare(candidatePassword, this.password, (err, isMatch) => {
    if(err) {
      return callback(err)
    } else {
      callback(null, isMatch)
    }
  })
}

//Create model class
const ModelClass = mongoose.model('User', userSchema);

//export model
module.exports = ModelClass;