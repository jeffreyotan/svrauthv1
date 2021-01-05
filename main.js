// include required libraries and modules
const express = require('express');
const morgan = require('morgan');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');

// Passport core
const passport = require('passport');
// Passport strategy
const LocalStrategy = require('passport-local').Strategy;

// configure PORT
const PORT = parseInt(process.argv[2]) || parseInt(process.env.PORT) || 3000;

// configure database
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PW,
    database: process.env.DB_NAME || 'paf2020',
    connectionLimit: parseInt(process.env.DB_CONN_LIMIT) || 4,
    timezone: '+08:00'
});

const makeQuery = (sql, dbPool) => {
    console.info('=> Creating query: ', sql);
    return (async (args) => {
        const conn = await dbPool.getConnection();
        try {
            let results = await conn.query(sql, args) || [];
            return results[0];
        } catch (e) {
            console.error('=> Unable to create query: ', e);
        } finally {
            conn.release();
        }
    });
};

SQL_QUERY_USER_INFO = "select user_id from user where user_id = ? and password = sha1(?)";

const queryUser = makeQuery(SQL_QUERY_USER_INFO, pool);

const TOKEN_SECRET = "secret";

// helper function to ensure that the express server can start up properly
const startApp = async (newApp, newPool) => {
    try {
        const conn = await newPool.getConnection();

        console.info('We are pinging the database..');
        await conn.ping();

        // at this point, if an error occurred, the error will be thrown and caught in the catch segment.
        // Otherwise, it is safe to assume that the connection was successful.
        conn.release();

        newApp.listen(PORT, () => {
            console.info(`Server start at port ${PORT} on ${new Date()}`);
        });
    } catch (e) {
        console.error('=> Unable to establish a connection to the database!', e);
    }
}

// configure Passport with a strategy
passport.use(
    new LocalStrategy(
        { usernameField: 'username', passwordField: 'password', passReqToCallback: true },
        async (req, user, password, done) => {
            // perform the authentication
            console.info(`=> Received user:${user} and password:${password}`);
            const userInfo = await queryUser([user, password]);
            console.info('=> userInfo: ', userInfo);
            let authResult = false; // (user == password);
            if (userInfo && userInfo.length > 0) {
                authResult = true;
                console.info('=> Setting authResult to true!');
            }
            if (authResult) {
                done(null,
                    // info about the user
                    { username: user, loginTime: (new Date()).toString(), security: 2 }
                );
                return;
            }
            // incorrect login
            done('Incorrect username and password', false);
        }
    )
);

const makeAuth = (newPassport) => {
    return (req, res, next) => {
        newPassport.authenticate('local',
            (err, user, info) => {
                if((err != null) || !user) {
                    res.status(401).contentType('application/json').json({ error: err });
                    return;
                }
                req.user = user;
                next();
            }
        )(req, res, next);
    }
}

const localStrategyAuth = makeAuth(passport);

// create an instance of the express server
const app = express();

// define middleware and routes
app.use(morgan('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// initialise passport after json and form-urlencoded has been processed
app.use(passport.initialize());

/* passport implementation with default error handling
app.post('/login', passport.authenticate('local', { session: false }), (req, res, next) => {
    console.info('user: ', req.user);
    // generate JWT token
    res.status(200).contentType('application/json').json({ message: `Login at ${new Date()}`});
}); */

/* passport implementation without using closure
app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if(err != null) {
            res.status(401).contentType('application/json').json({ error: err });
            return;
        }
        next();
    })(req, res, next); // do note that we have to manually call the middleware to handle the inputs
}, (req, res, next) => {
    console.info('user: ', req.user);
    // generate JWT token
    const token = jwt.sign({
        sub: req.user.username,
        iss: 'myapp',
        iat: (new Date()).getTime() / 1000,
        data: {
            loginTime: req.user.loginTime
        }
    }, TOKEN_SECRET);

    res.status(200).contentType('application/json').json({ message: `Login at ${new Date()}`});
}); */

/* passport authentication with closure function */
app.post('/login', localStrategyAuth, (req, res, next) => {
    console.info('user: ', req.user);
    // generate JWT token
    const currTime = (new Date()).getTime(); // note that the time given is in milliseconds
    const token = jwt.sign({
        sub: req.user.username,
        iss: 'myapp',
        iat: currTime / 1000,
        // nbf: (currTime / 1000) + 15, // can only be used 15 seconds later
        exp: (currTime / 1000) + 30, // for the token to expire 30 seconds later
        data: {
            loginTime: req.user.loginTime
        }
    }, TOKEN_SECRET);

    res.status(200).contentType('application/json').json({ message: `Login at ${new Date()}` ,token: token });
});

app.get('/protected/secret', (req, res, next) => {
    // check if the request has Authorization header
    const auth = req.get('Authorization');
    if (auth == null) {
        res.status(401).contentType('application/json').json({ message: 'Cannot access' });
        return;
    }
    // bearer authorization
    const terms = auth.split(' ');
    if ((terms.length != 2) || (terms[0] != 'Bearer')) {
        res.status(401).contentType('application/json').json({ message: 'incorrect Authorization' });
        return;
    }
    const token = terms[1];
    try {
        const verified = jwt.verify(token, TOKEN_SECRET);
        console.info("Verified token: ", verified);
        req.token = verified;
        next();
    } catch (e) {
        res.status(403).contentType('application/json').json({ message: "Incorrect token", error: e});
    }
}, (req, res, next) => {
    res.status(200).contentType('application/json').json({ meaning_of_life: 42 });
});

// start the express server
startApp(app, pool);
