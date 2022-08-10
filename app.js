require("dotenv").config();
const express = require("express");
const app = express();
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const e = require("express");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true
}))

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    username:
    {
        type: String,
    },
    password:
    {
        type: String
    },
    googleId: {
        type: String
    }
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const users = new mongoose.model("user", userSchema);

// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(users.createStrategy());

// used to serialize the user for the session
passport.serializeUser(function(user, done) {
    done(null, user.id); 
   // where is this user.id going? Are we supposed to access this anywhere?
});

// used to deserialize the user
passport.deserializeUser(function(id, done) {
    users.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        users.findOrCreate({ googleId: profile.id, username: profile.displayName }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", (req, res) => {
    res.render("home");
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/register' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.render("secrets");
    }
);

app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
})

app.get("/logout", (req, res, next) => {
    req.logout((err) => {
        if (err) {
            console.log(err);
            return next(err);
        }
        res.redirect("/");
    });
})

app.route("/register")

    .get((req, res) => {
        res.render("register");
    })

    .post((req, res) => {
        users.findOne({ username: req.body.username }, (err, doc) => {
            console.log(doc);
            if (doc) {
                res.redirect("/login");
            } else {
                users.register({ username: req.body.username }, req.body.password, (err, user) => {
                    if (err) {
                        console.log(err);
                        res.redirect("/register");
                    } else {
                        passport.authenticate("local")(req, res, () => {
                            res.redirect("/secrets");
                        })
                    }
                });
            }
        });
    })

app.route("/login")

    .get((req, res) => {
        if (req.isAuthenticated()) {
            res.redirect("/secrets");
        } else {
            res.render("login");
        }
    })

    .post((req, res) => {
        const user = new users({
            username: req.body.username,
            password: req.body.password
        });

        req.login(user, (err) => {
            if (err) {
                console.log(err);
            } else {
                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets");
                })
            }
        })
    })

app.listen(3000, () => {
    console.log("Hosted on Port 3000");
})