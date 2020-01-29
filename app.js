//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const ejs = require("ejs");
const _ = require("lodash");
//const encrypt = require("mongoose-encryption");

//encryption using hashing
//const md5 = require("md5");

//use bcrypt for salting i.e. multiple hashing
// const bcrypt = require("bcrypt");
// const saltRounds = 10;

//authentication using passport
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");

//OAuth authentication
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const TwitterStrategy = require('passport-twitter').Strategy;

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

//should be written at this place only
app.use(session({
  secret: "Myencryptionstring",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());

app.use(passport.session());

//connect to mongoose Server
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  autoIndex: false
});
mongoose.set('useCreateIndex', true);

const secretSchema = new mongoose.Schema({
  secret: String
});

const Secret = new mongoose.model("Secret", secretSchema);

const userSchema = new mongoose.Schema({
  name: {type: String, sparse:true},
  email: String,
  password: String,
  googleId: String,
  twitterId: String,
  facebookId: String,
  secrets: [secretSchema]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//encrypting the password field

//encrypting using environment variables
//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({
      googleId: profile.id,
      username: profile.displayName
    }, function(err, user) {
      return cb(err, user);
    });
  }
));


passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      facebookId: profile.id,
      username: profile.displayName
    }, function(err, user) {
      return cb(err, user);
    });
  }
));


passport.use(new TwitterStrategy({
    consumerKey: process.env.TWITTER_CONSUMER_KEY,
    consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
    callbackURL: "http://localhost:3000/auth/twitter/secrets"
  },
  function(token, tokenSecret, profile, cb) {
    console.log(profile);
    User.findOrCreate({
      twitterId: profile.id,
      username: profile.displayName
    }, function(err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res) {
  res.render("home");
});

// app.get("/auth/google", function(req, res){
//   passport.authenticate("google", { scope: ["profile"] })
// });

app.get("/auth/google", passport.authenticate('google', {

  scope: ['profile']

}));

app.get("/auth/google/secrets",
  passport.authenticate('google', {
    failureRedirect: "/login"
  }),
  function(req, res) {
    // Successful authentication, redirect to secrets which is our home page.
    res.redirect('/secrets');
  });


app.get('/auth/facebook', passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


app.get('/auth/twitter',
  passport.authenticate('twitter'));

app.get('/auth/twitter/secrets',
  passport.authenticate('twitter', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });



app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

//if user is already loged in i.e. if cookie is there than go to secrets page
app.get("/secrets", function(req, res) {
  //see whether users are there or not with secrets submitted i.e. their secret have atleast one element
  User.find({
    "secrets": {
      $ne: null
    }
  }, function(err, foundUsers) {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {
          usersWithSecrets: foundUsers
        });
      }
    }
  });
});


//after a user clicks submit button direct them to this submit page,
//to submit a request a user has to be authenticated
app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});


//if a person wants to see what secrets he have submitted
app.get("/yourSecrets", function(req, res) {
  if (req.isAuthenticated()) {
    //console.log(req.user);
    User.findById(req.user.id, function(err, foundUser) {
      res.render("yourSecrets", {
        yourSecrets: foundUser.secrets,
        name: foundUser.name
      });
    });
  } else {
    res.redirect("/login");
  }
});


//if a user wants to delete a secret he has submitted Thisisastringtoencryptthepassword
app.post("/delete", function(req, res) {
  if (req.isAuthenticated()) {
    User.findOneAndUpdate({
      _id: req.user.id
    }, {
      $pull: {
        secrets: {
          _id: req.body.checkBox
        }
      }
    }, function(err, foundList) {
      if (!err) {
        res.redirect("/yourSecrets");
      }
    });
  } else {
    res.redirect("/login");
  }
});


//save a new secret to the users secret array
app.post("/submit", function(req, res) {
  const sumittedSecret = req.body.secret;
  const newSecret = new Secret({
    secret: sumittedSecret
  });
  User.findById(req.user.id, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secrets.push(newSecret);
        foundUser.save(function() {
          res.redirect("/secrets");
        });
      }
    }
  });
});


//deauthenticate when user logout i.e. dlete the cookie
app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});


app.post("/register", function(req, res) {

  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   // Store hash in your password DB.
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //   });
  //
  //   newUser.save(function(err) {
  //     if (!err) {
  //       res.render("secrets");
  //     } else
  //       console.log(err);
  //   });
  //
  // });

  //<----------using passport---------->
  //{username: req.body.username}, req.body.password,  {name: req.body.name}, username: req.body.username, req.body.password
  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });



});


//creating login page
app.post("/login", function(req, res) {
  // const username = req.body.username;
  // const password = req.body.password;
  //
  // User.findOne({
  //   email: username
  // }, function(err, foundUser) {
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     if (foundUser) {
  //       bcrypt.compare(password, foundUser.password, function(err, result) {
  //         // result == true
  //         if (result === true)
  //           res.render("secrets");
  //       });
  //
  //     }
  //   }
  // });

  //<----------using passport---------->
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err) {
    if (err)
      console.log(err);
    else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });

});


app.listen(3000, function() {
  console.log("Server started on port 3000");
});
