//jshint esversion:6

require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const session = require('express-session');
const passport = require('passport');
const findOrCreate = require('mongoose-findorcreate');
const passportLocalMongoose = require('passport-local-mongoose');
//////// for md5
// const md5 = require("md5");


//////// for bcrypt
const bcrypt = require("bcrypt");
const saltRounds = 10;

// google authenticate
const GoogleStrategy = require('passport-google-oauth20').Strategy;


const app = express();

// console.log(process.env.API_KEY);

app.use(express.static("public"));
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: 'our little Secret.',
  resave: false,
  saveUninitialized: true,
  // cookie: { secure: true }
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/userDB');
// mongoose.set("useCreateIndex",true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


// first encrypt password method form .env
// const sceret = "this is our sceret text"
// userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]});

const User = new mongoose.model("User", userSchema);

// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res) {
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', {
    scope: ["profile"]
  }));

app.get("/auth/google/secrets", passport.authenticate('google', {
  failureRedirect: '/login'
}), function(req, res) {
  // Successful authentication, redirect home.
  res.redirect('/secrets');
});

app.post("/", function(req, res) {
  res.render("home")
});

app.get("/register", function(req, res) {
  res.render("register")
});

app.post("/register", function(req, res) {

  User.register({username: req.body.username}, req.body.password, function(err, user) {
    if (err) {
      res.send(err)
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
  //  bcrypt.hash(req.body.password, saltRounds ,function(err , hash){
  //    const newUser = new User({
  //      email:req.body.username,
  //      password:hash
  //    });
  //
  //    newUser.save(function(err){
  //      if (err) {
  //        res.send(err)
  //      } else {
  //        res.render("Secrets")
  //      }
  //    });
  // });
});


app.get("/secrets", function(req, res) {
  // if (req.isAuthenticated()) {
  //   res.render("secrets");
  //   } else {
  //   res.redirect("/login")
  // }

  User.find({"secret": {$ne: null}}, function(err, foundUser) {
    if (err) {
      console.log(err);
      // res.send(err);
    } else {
      if (foundUser) {
        res.render("secrets", {userWithSecrets:foundUser});
      }
    }
  });
});

app.post("/Secrets", function(req, res) {
  res.render("Secrets")
});


app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login")
  }
});
app.post("/submit", function(req, res) {
  const submittedSecret = req.body.secret;


//Once the user is authenticated and their session gets saved, their user details are saved to req.user.
  // console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser) {
    if (err) {
      res.send(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function() {
          res.redirect("/secrets");
        });
      }
    }
  });
});



app.get("/login", function(req, res) {
  res.render("login");
});


app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});


app.get("/logout", function(req, res) {
  req.logout();
  res.render("/");
});

app.post("/logout", function(req, res) {
  res.render("home")
});


app.listen(3000, function() {
  console.log("Server started on port 3000");
});
