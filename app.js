var express = require('express');
var passport = require('passport');
var mongoose = require('mongoose');
var BearerStrategy = require('passport-http-bearer').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;

var app = express();

const MONGO = {
    URL: 'mongodb://localhost/testdb'
}

const FACEBOOK = {
    NAME: 'facebook',
    APP_ID: "305117229820764",
    APP_SECRET: "54ba3a50826c9e55b59c9d30ce1a983f",

    OUT_URL: '/auth/facebook',
    BACK_URL: '/auth/facebook/callback'
}

/**
 * Setup Mongo DB
 */
mongoose.connect(MONGO.URL);
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

UserSchema.statics.findAndRemove = function(filters, cb) {
    User = this;
    this.find(filters, function(err, results) {
        if(err){
            console.log("Failed to retrieve user. Error: ", err);
            cb(err);
        } else {
            for(var i=0; i<results.length; i++){

                console.log("Removing user: ", results[i]);
                results[i].remove(function(err){
                    if(err){
                        console.log("Failed to remove user. Error: ", err);
                    } else {
                        console.log("Removed user.");
                    }
                    cb(err);
                });
            }
        }
    });
};

var User = mongoose.model('User', UserSchema);

/**
 *
 * Authenticated by Facebook initially
 */
options = {
    clientID: FACEBOOK.APP_ID,
    clientSecret: FACEBOOK.APP_SECRET,
    callbackURL: FACEBOOK.BACK_URL
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
                    return done(null, user,
                        {
                            //set by Passport at req.authInfo to be used by later middleware for authorization and access control.
                            scope: 'all'
                        }
                    );
                }
            );
        }
    )
);

/**
 * HTML routing setup
 */
app.get('/',
    function(req, res) {
        res.send(`<a href="${FACEBOOK.BACK_URL}">Log in</a>`);
    }
);

// Use something like Redis and set a ttl on the token, so the token is removed automatically after some time.
app.get('/logout',
        function(req, res){
        req.logout();   //Invoking logout() will remove the req.user property and clear the login session

        var access_token = req.query.access_token;
        console.log("Log out acess token: ", access_token);

        User.findAndRemove(
            {
                access_token: access_token
            },
            function (err) {

                if(!err) {
                    console.log("Logged out user with token: ", access_token);
                } else {
                    console.log("Failed to logged out user. Error: ", err);
                }
            }
        );

        res.redirect('/');
    }
);

app.get('/profile',
    passport.authenticate('bearer',
        {
            // Requests containing bearer tokens do not require session support,
            // so the session option can be set to false
            session: false
        }
    ),
    function(req, res) {
        res.send(
            `LOGGED IN as ${req.user.facebookId} - \
            <a href="/logout?access_token=${req.user.access_token}">\
                Log out\
            </a>`
        );
    }
);

app.get(
    FACEBOOK.OUT_URL,
    passport.authenticate(FACEBOOK.NAME,
        {
            session: false,
            //Specify what to take from FB
            scope: []
        }
    )
);

app.get(FACEBOOK.BACK_URL,
    passport.authenticate(FACEBOOK.NAME,
        {
            session: false,
            failureRedirect: "/"
        }
    ),
    function(req, res) {

        //The HTTP Bearer authentication strategy authenticates requests based on a bearer token contained in the:
        // 1. authorization header field where the value is in the format {scheme} {token} and scheme is "Bearer" in this case.
        // 2. access_token body parameter
        // 3. access_token query parameter
        res.redirect(`/profile?access_token=${req.user.access_token}`);
    }
);

app.listen(3000);

