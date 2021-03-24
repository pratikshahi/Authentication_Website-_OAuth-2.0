//jshint esversion:6
require("dotenv").config(); //using dotenv to encrypt,always put on top
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session"); //for passport method of authentication require all 3
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy; //for google-oauth20
const findOrCreate = require("mongoose-findorcreate"); //to use sudocode by passport find or create we install mongoose-findoecreate package

const app = express();

app.set("view engine", "ejs");

app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);
app.use(express.static("public"));
//made sessions
app.use(
  session({
    secret: "This is our secret text",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize()); //initialize Passport
app.use(passport.session()); //made passport to manage session

mongoose.connect("mongodb://localhost:27017/authWebUserDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
mongoose.set("useCreateIndex", true); //to remove deprecation warning
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  posts: String,
});

userSchema.plugin(passportLocalMongoose); //made userSchema to use passportlocalmongose as plugin

userSchema.plugin(findOrCreate); //made user schema to use findorcreate as plugin

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy()); //created local login strategy to serailze and deserailize

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});
/////////////////////////////////using google oauth2.0
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo", //using user google profile
    },
    function (accessToken, refreshToken, profile, cb) {
      //see what google send us back
      console.log(profile);
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        //to use sudocode by passport find or create we install mongoose-findoecreate package
        return cb(err, user);
      });
    }
  )
);

app.route("/").get(function (req, res) {
  res.render("home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect to secret page.
    res.redirect("/secrets");
  }
);
app
  .route("/submit")
  .get(function (req, res) {
    if (req.isAuthenticated()) {
      //check if user is authenticated
      res.render("submit");
    } else {
      res.redirect("/login");
    }
  })
  .post(function (req, res) {
    const submittedPost = req.body.secret;
    console.log(req.user.id);
    User.findById(req.user.id, function (err, foundItem) {
      if (err) {
        console.log(err);
      } else {
        if (foundItem) {
          foundItem.posts = submittedPost;
          foundItem.save(function () {
            res.redirect("/secrets");
          });
        }
      }
    });
  });

app
  .route("/register")
  .get(function (req, res) {
    res.render("register");
  })
  .post(function (req, res) {
    //register is method from passpot local mongoose
    User.register(
      { username: req.body.username },
      req.body.password,
      function (err, user) {
        if (err) {
          console.log(err);
          res.redirect("/register");
        } else {
          passport.authenticate("local")(req, res, function () {
            res.redirect("/secrets");
          });
        }
      }
    );
  });

app
  .route("/login")
  .get(function (req, res) {
    res.render("login");
  })
  .post(function (req, res) {
    const user = new User({
      username: req.body.username,
      password: req.body.password,
    });
    //login method comes from passport
    req.login(user, function (err) {
      if (err) {
        console.log(err);
      } else {
        passport.authenticate("local")(req, res, function () {
          //authenticate user
          res.redirect("/secrets");
        });
      }
    });
  });

app
  .route("/secrets")

  .get(function (req, res) {
    if (req.isAuthenticated()) {
      //check if user is authenticated
      res.render("secrets");
    } else {
      res.redirect("/login");
    }
  });

app
  .route("/logout")

  .get(function (req, res) {
    req.logout();
    res.redirect("/");
  });

app.listen(3000, function () {
  console.log("Server started on port 3000");
});
