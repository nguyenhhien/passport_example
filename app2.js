var express = require('express');
var passport = require('passport');
var flash = require('connect-flash');
var utils = require('./utils');
var LocalStrategy = require('passport-local').Strategy;
var RememberMeStrategy = require('passport-remember-me').Strategy;

var REMEMBERME_TOKEN_COOKIE_NAME = 'remember_me';

/**
 * User Database
 */
var users_db = [
    { id: 1, username: 'bob', password: 'secret', email: 'bob@example.com' },
    { id: 2, username: 'joe', password: 'birthday', email: 'joe@example.com' }
];

function findById(id, fn) {
    var idx = id - 1;
    if (users_db[idx]) {
        fn(null, users_db[idx]);
    } else {
        fn(new Error('User ' + id + ' does not exist'));
    }
}

function findByUsername(username, fn) {
    for (var i = 0, len = users_db.length; i < len; i++) {
        var user = users_db[i];
        if (user.username === username) {
            return fn(null, user);
        }
    }
    return fn(null, null);
}

/**
 * Remember Me Database
 */
var rememberme_tokens_db = {};

function consumeRememberMeToken(token, fn) {
    var uid = rememberme_tokens_db[token];
    // invalidate the single-use token
    delete rememberme_tokens_db[token];
    return fn(null, uid);
}

function saveRememberMeToken(token, uid, fn) {
    rememberme_tokens_db[token] = uid;
    return fn();
}

/**
 * Passport session setup - To support persistent login sessions
 */
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    findById(id, function (err, user) {
        done(err, user);
    });
});

/**
 * Authentication
 */
passport.use(new LocalStrategy(
    function(username, password, done) {
        // asynchronous verification, for effect...
        process.nextTick(function () {

            findByUsername(username, function(err, user) {
                if (err) {
                    return done(err);
                }
                if (!user) {
                    return done(null, false,
                        {
                            message: 'Unknown user ' + username
                        }
                    );
                }
                if (user.password != password) {
                    return done(null, false,
                        {
                            message: 'Invalid password'
                        }
                    );
                }
                return done(null, user);
            })
        });
    }
));

// Remember Me cookie strategy
//   This strategy consumes a remember me token, supplying the user the
//   token was originally issued to.
passport.use(new RememberMeStrategy(

    function verifyCb(token, done) {
        consumeRememberMeToken(token, function(err, uid) {
            if (err) { return done(err); }
            if (!uid) { return done(null, false); }

            findById(uid, function(err, user) {
                if (err) { return done(err); }
                if (!user) { return done(null, false); }
                return done(null, user);
            });
        });
    },
    //The token is single-use, so a new token is then issued to replace it
    issueToken
));

function issueToken(user, done) {
    var token = utils.randomString(64);
    saveRememberMeToken(token, user.id, function(err) {
        if (err) {
            return done(err);
        }
        return done(null, token);
    });
}

/**
 * middleware
 */
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login')
}

var app = express();

app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.engine('ejs', require('ejs-locals'));
app.use(express.logger());
app.use(express.static(__dirname + '/../../public'));
app.use(express.cookieParser());
app.use(express.bodyParser());
app.use(express.methodOverride());
app.use(express.session({ secret: 'keyboard cat' }));
app.use(flash());

/**
 * Initialize Passport
 */
app.use(passport.initialize());
app.use(passport.session()); //use passport.session() middleware, to support persistent login sessions (recommended)
app.use(passport.authenticate('remember-me'));

app.use(app.router);

//Login page
app.get('/login', function(req, res){
    res.render('login',
        {
            user: req.user,
            message: req.flash('error')
        }
    );
});

//Home page
app.get('/', function(req, res){
    res.render('index',
        {
            user: req.user
        }
    );
});

/**
 * Account page
 * Cookie:remember_me=WRPCg8xzA6BZuqOfamHOgmhvafpU37cu7sgmuwh9VCBmhQt90BxlKfHflKBBIl9k;
 * Cookie: connect.sid=s%3AWmI4CIMEkR_89MZWFzWn_2K13iodkM2z.qWXaJguEAT6aU8e6auvcbtw07WilagXVUHfLVBm%2BSYY
 */
app.get('/account',
    ensureAuthenticated,
    function(req, res){

        console.log("req.session: ", JSON.stringify(req.session));
        console.log("req.user: ", JSON.stringify(req.user));

        res.render('account',
            { user: req.user }
        );
    }
);

// login api
app.post('/login',
    passport.authenticate('local',
        {
            failureRedirect: '/login',
            failureFlash: true
        }
    ),
    function handleRememberMe(req, res, next) {
        if (!req.body.remember_me) {
            return next();
        } else {
            issueToken(req.user, function(err, token) {
                if (err) {
                    return next(err);
                }
                res.cookie(REMEMBERME_TOKEN_COOKIE_NAME, token,
                    {
                        path: '/',
                        httpOnly: true,
                        maxAge: 604800000
                    }
                );
                return next();
            });
        }
    },
    function(req, res) {
        res.redirect('/');
    }
);

// logout api
app.get('/logout', function(req, res){
    res.clearCookie(REMEMBERME_TOKEN_COOKIE_NAME);
    req.logout();
    res.redirect('/');
});

app.listen(3000, function() {
    console.log('Express server listening on port 3000');
});
