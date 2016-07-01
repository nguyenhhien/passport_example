var express = require('express');
var passport = require('passport');
var mongoose = require('mongoose');
var BearerStrategy = require('passport-http-bearer').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;

var app = express();

var FACEBOOK_APP_ID = "305117229820764";
var FACEBOOK_APP_SECRET = "54ba3a50826c9e55b59c9d30ce1a983f";

app.configure(function() {

    /**
     * Setup Mongo DB
     */
    mongoose.connect('mongodb://localhost/testdb');

    var UserSchema = new mongoose.Schema({
        facebookId: {
            type: String
        },
        access_token: {
            type: String
        },
    });

    UserSchema.statics.findOrCreate = function(filters, cb) {
        User = this;
        this.find(filters, function(err, results) {
            if(results.length == 0) {
                var newUser = new User();
                newUser.facebookId = filters.facebookId;
                newUser.save(function(err, doc) {
                    cb(err, doc)
                });
            } else {
                cb(err, results[0]);
            }
        });
    };

    var User = mongoose.model('User', UserSchema);

    /**
     *
     * Authenticated by Facebook initially
     */
    options = {
        clientID: FACEBOOK_APP_ID,
        clientSecret: FACEBOOK_APP_SECRET,
        callbackURL: 'http://localhost:3000/auth/facebook/callback'
    };

    passport.use(
        new FacebookStrategy(
            options,
            function(accessToken, refreshToken, profile, done) {
                User.findOrCreate(
                    {
                        facebookId: profile.id
                    },
                    function (err, result) {

                        if(result) {
                            console.log("Found/Created user: " + JSON.stringify(result));
                            result.access_token = accessToken;
                            result.save(function(err, doc) {
                                if(err){
                                    console.log("Failed to save user: ", err);
                                } else {
                                    console.log("Saved user: ", doc);
                                }

                                done(err, doc);
                            });
                        } else {
                            console.log("Failed to retrieve/create user. Error: ", err);
                            done(err, result);
                        }
                    }
                );
            }
        )
    );

    app.get(
        '/auth/facebook',
        passport.authenticate('facebook',
            {
                session: false,
                scope: []
            }
        )
    );

    app.get('/auth/facebook/callback',
        passport.authenticate('facebook',
            {
                session: false,
                failureRedirect: "/"
            }
        ),
        function(req, res) {
            res.redirect("/profile?access_token=" + req.user.access_token);
        }
    );

    /**
     * Using a token in subsequent request
     */
    passport.use(
        new BearerStrategy(
            function(token, done) {
                console.log("Received token: " + token);
                User.findOne(
                    {
                        access_token: token
                    },
                    function(err, user) {
                        if(err) {
                            console.log("Failed (system) to retrieve user from token: ", token);
                            return done(err);
                        }
                        if(!user) {
                            console.log("Failed (not found) to retrieve user from token: ", token);
                            return done(null, false);
                        }

                        console.log("Retrieved user: ", user , " from token: ", token);
                        return done(null, user, { scope: 'all' })
                    }
                );
            }
        )
    );
});


/**
 * HTML routing setup
 */
app.get(
    '/',
    function(req, res) {
        res.send('<a href="/auth/facebook">Log in</a>');
    }
);

app.get(
    '/profile',
    passport.authenticate('bearer', { session: false }),
    function(req, res) {
        res.send("LOGGED IN as " + req.user.facebookId + " - <a href=\"/logout\">Log out</a>");
    }
);

app.listen(3000);
