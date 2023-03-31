const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const User = require('./models/User');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;

const cookieExtractor = (req) => {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies['access_token'];
  }
  return token;
};

passport.use(
  new JwtStrategy(
    {
      jwtFromRequest: cookieExtractor,
      secretOrKey: 'ethantjackson',
    },
    (payload, done) => {
      User.findById({ _id: payload.sub }, (err, user) => {
        if (err) return done(err, false);
        if (user) return done(null, user);
        else return done(null, false);
      });
    }
  )
);

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_ID,
      clientSecret: process.env.GOOGLE_SECRET,
      callbackURL: '/user/auth/google/callback',
      proxy: true,
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        { googleId: profile.id, name: profile.displayName },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_ID,
      clientSecret: process.env.FACEBOOK_SECRET,
      callbackURL: '/user/auth/facebook/callback',
      proxy: true,
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        { facebookId: profile.id, name: profile.displayName },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

passport.use(
  new LocalStrategy(
    { usernameField: 'email', passwordField: 'password' },
    (email, password, done) => {
      User.findOne({ email }, (err, user) => {
        if (err) {
          return done(err);
        }
        if (!user) {
          return done(null, false);
        }
        user.comparePassword(password, done);
      });
    }
  )
);
