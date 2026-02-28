var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var mongoose = require("mongoose");
require("./models")
var bcrypt = require("bcrypt")
var expressSession = require("express-session");
var passport = require("passport");
var LocalStrategy = require("passport-local").Strategy;

const stripeSecretKey = process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder';
const stripe = require('stripe')(stripeSecretKey);
var User = mongoose.model("User");

// Connect to MongoDB (local or memory server)
async function connectDB() {
  const { MongoMemoryServer } = require('mongodb-memory-server');
  const mongod = await MongoMemoryServer.create();
  const uri = mongod.getUri();
  console.log('Using in-memory MongoDB at:', uri);
  await mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });
}

connectDB().catch(err => {
  console.error('Failed to connect to MongoDB:', err);
  process.exit(1);
});

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(expressSession({
  secret: "yet4n5a6ve86seatbj4hnd2mb86tb1486hfwevt2346twf4gv1x5bcg4f5tv44h1n4rnyi5c"
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy({
  usernameField: "email",
  passwordField: "password"
}, function(email, password, next) {
  User.findOne({
      email: email
  }, function(err, user) {
      if (err) return next(err);
      if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
          return next({message: 'Email or password incorrect'})
      }
      next(null, user);
  })
}));

passport.use('signup-local', new LocalStrategy({
  usernameField: "email",
  passwordField: "password"
}, function(email, password, next) {
  User.findOne({
      email: email
  }, function(err, user) {
      if (err) return next(err);
      if (user) return next({message: "User already exists"});
      let newUser = new User({
          email: email,
          passwordHash: bcrypt.hashSync(password, 10)
      })
      newUser.save(function(err) {
          next(err, newUser);
      });
  });
}));

passport.serializeUser(function(user,next) {
  next(null, user._id);
});

passport.deserializeUser(function(id,next) {
  User.findById(id, function(err, user) {
    next(err, user);
  });
});

app.get("/", function(req, res, next) {
  res.render("index",{title: "SaasApp"})
});

app.get("/billing", async function(req, res, next) {

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price: 'price_1H5GBtC42zE1cBpbUKFR68BK',
        quantity: 1,
      }],
      mode: 'subscription',
      success_url: `${process.env.APP_URL || 'http://localhost:3000'}/main?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.APP_URL || 'http://localhost:3000'}/billing`,
    }, function(err, session) {
      if (err) return next(err);
      res.render("billing", {sessionId: session.id, subscriptionActive: req.user.subscriptionActive})
    });
});

app.post('/login',
  passport.authenticate('local', { failureRedirect: '/login-page' }),
  function(req, res) {
    res.redirect('/main');
});

app.post('/signup',
  passport.authenticate('signup-local', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/main');
});



app.get("/login-page", function(req, res, next) {
  res.render("login-page")
});

app.get("/main", function(req, res, next) {
  res.render("main")
});

app.get("/signup-page", function(req, res, next) {
  res.render("signup-page")
});

app.get("/logout", function(req, res, next) {
  req.logout();
  res.redirect("/");
});


// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
