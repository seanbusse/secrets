//jshint esversion:6

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const _ = require('lodash');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate')
const https = require('https');
const fs = require('fs');
const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

const sslData = {
  key: fs.readFileSync('public/SSL/server.key'),
  cert: fs.readFileSync('public/SSL/server.crt')
};

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

const dbUrl = process.env.MONGO_DB;
mongoose.connect(dbUrl, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useFindAndModify: false,
});


//Create the user schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: {
    type: String,
    default: null
  },
  lastPosted: Date
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model('User', userSchema);

// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: 'https://localhost:3000/auth/google/secrets',
  passReqToCallback: true
}, 
function(request, accessToken, refreshToken, profile, done) {
  console.log(profile)
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return done(err, user);
  });
}
));

passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: 'https://localhost:3000/auth/facebook/secrets'
},
function(accessToken, refreshToken, profile, done) {
  User.findOrCreate({facebookId: profile.id}, function(err, user) {
    console.log(profile);
    if (err) { return done(err); }
    done(null, user);
  });
}
));


let redirect = 'Please log in for this resource.';

app.route('/')

  .get(function (req, res) {
    res.render('home');
  });

app.route('/register')

  .get(function (req, res) {
    res.render('register', { message: '', redirect: '' });
  })

  .post(function (req, res) {

    User.register({username: req.body.username}, req.body.password, function(err, user) {
      if(err) {
        console.log(err);
        res.render('register', {message: 'There was a problem with your registration.'});
      } else {
        passport.authenticate('local')(req, res, function() {
          res.redirect('/submit');
        });
      }
    });
  });

app.route('/login')

  .get(function (req, res) {
    res.render('login', { message: '', redirect: '' });
  })

  .post(function(req, res) {

    const user = new User({
      username: req.body.username,
      password: req.body.password
    });

    req.login(user, function(err) {
      if (err) {
        console.log(err);
      } else {
        passport.authenticate('local')(req, res, function() {
          res.redirect('/submit');
        });
      }
    });
  });


app.route('/submit')

  .get(function (req, res) {
    if (req.isAuthenticated()) {
      res.render('submit', {bodyClass: 'submit', systemMessage: ''});
    }
    else {
      res.redirect('/Login');
    }
  })

  .post(function(req, res) {
    User.findByIdAndUpdate(req.user.id, {secret: req.body.secret}, function(err, foundUser) {
      if (err) {
        console.log(err);
      } else {
        if(foundUser) {
          res.redirect('/secrets');
        }
      }
    })
  });

app.get('/logout', function (req, res) {
    req.logout();
    res.redirect('/');
  });

app.get('/secrets', function (req, res) {
      User.find({secret: {$ne: null}}, function(err, foundSecrets) {
        if(err) {
          console.log(err);
        } else {
          if(foundSecrets) {
            console.log(foundSecrets);
            res.render('secrets', { bodyClass: 'secrets', secrets: foundSecrets });
          }
        }
      });
  });

app.get('/auth/google', passport.authenticate('google', { scope: ['email', 'profile'] }));

app.get( '/auth/google/secrets', passport.authenticate( 'google', { successRedirect: '/secrets', failureRedirect: '/login' }));

app.get('/auth/facebook',  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets', passport.authenticate('facebook', { successRedirect: '/secrets', failureRedirect: '/login' }));



//Define the server listening port
let port = process.env.PORT;
if (port == null || port == '') {
  port = 3000;
}
// app.listen(port, function () {
//   console.log('Server started successfully');
// });

https.createServer(sslData, app).listen(port);
