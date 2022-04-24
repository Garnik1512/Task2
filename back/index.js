import express from "express";
import session from "express-session";
import path from "path";
import bcrypt from "bcrypt";
import passport from "passport";
import passportLocal from "passport-local";


let users = [];
const app = express();

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(express.json());

app.use(express.urlencoded({ extended: true }));

app.use(express.static('front'));

app.use(passport.initialize());

app.use(passport.session());

passport.use(new passportLocal.Strategy({
    usernameField: "email"
}, async (email, password, done) => {
    const user = users.find((user) => user.email === email);

    if (user === undefined) {
        return done(null, null, { massage: "Incorrect email" });
    }
    if (await bcrypt.compare(password, user.password)) {
        return done(null, user)
    }
    done(null, null, { massage: "Incorrect password" });
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    done(null, users.find((user) => user.id === id));
});



app.get("/register" , checkNotAuthentication,  (req, res) => {
    res.sendFile(path.resolve("front/reg.html"));
});

app.post("/register", async (req, res) => {

    const { name, lastname, tel, email, password } = req.body;
    const hashedPwd = await bcrypt.hash(password, 10);
    users.push({
        id: `${Date.now()}_${Math.random()}`,
        name,
        lastname,
        tel,
        email,
        password: hashedPwd
    });
    res.redirect("/login");
});
app.get("/login", checkNotAuthentication, (req, res) => {
    res.sendFile(path.resolve("front/login.html"));

});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login"
}));
app.use(checkAuthentication);

app.get("/",checkAuthentication, (req, res) => {
    res.sendFile(path.resolve("front/project.html"));

});

app.get("/logout", (req, res) => {
    req.logOut();
    res.redirect("/project.html")
});

function checkAuthentication(req, res, next) {
    if (req.isAuthenticated() === false) {
        return res.redirect("/login");
    }
    next();
};
function checkNotAuthentication(req, res, next) {
    if (req.isAuthenticated() === true) {
        return res.redirect("/");
    }
    next();
}

app.listen(process.env.PORT)