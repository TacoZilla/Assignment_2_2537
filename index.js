require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');

const Joi = require('joi');
const saltRounds = 12

const app = express();

const port = process.env.port || 3018;

app.set("view engine", "ejs");
app.set("views", "./views");

app.use(express.urlencoded({ extended: true }));

app.use("/scripts", express.static("./Public/scripts"));
app.use("/styles", express.static("./Public/styles"));
app.use("/images", express.static("./Public/images"));

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = require('./connectionMongo');

const userCollection = database.db(mongodb_database).collection('users');

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    },
    ttl: 60 * 60
})

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}


function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!req.session.authenticated) {
        res.redirect('/login');
        return;
    }

    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {
            error: "Not Authorized",
            title: "Error",
            LoggedIn: req.session.authenticated, 
            user_type: req.session.user_type
        });
        return;
    }
    else {
        next();
    }
}

const expireTime = 1 * 60 * 60 * 1000;

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: { maxAge: 60 * 60 }
}
));

app.get("/", (req, res) => {

    res.render("Index", {
        LoggedIn: req.session.authenticated,
        username: req.session.username,
        user_type: req.session.user_type
    });
});


app.get('/createUser', (req, res) => {
    if (req.session.authenticated == true) {
        res.redirect('/members');
    }
    res.render('signup', { error: null,
         authenticated: false,
        LoggedIn: req.session.authenticated,});
});

app.post('/postUser', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ username, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        return res.render('signup', { error: validationResult.error.details[0].message, LoggedIn: false });
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        username: username,
        email: email,
        password: hashedPassword,
        user_type: "user"
    });
    console.log("Inserted user");


    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;
    req.session.user_type = "user";

    res.redirect('/members');

});

app.get('/login', (req, res) => {
    res.render('login', {
        error: req.query.error,
        LoggedIn: req.session.authenticated
    });
});

app.post('/loggingin', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login?error=Wrong username/password mix");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, user_type: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        res.redirect("/login");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;
        req.session.user_type = result[0].user_type;

        console.log(result[0].user_type)
        res.redirect('/members')
        return;
    }
    else {
        console.log("incorrect password");
        res.redirect("/login?error=Wrong username/password mix");
        return;
    }
});

app.post("/promote/:id", adminAuthorization, sessionValidation, async (req, res) => {
  const userId = req.params.id;
  await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: "admin" } });
  res.redirect("/admin");
});

app.post("/demote/:id", adminAuthorization, sessionValidation, async (req, res) => {
  const userId = req.params.id;
  await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: "user" } });
  res.redirect("/admin");
});


app.get("/admin", adminAuthorization, sessionValidation, async (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
        return;
    }
    if (req.session.user_type != 'admin') {
            res.status(403);
            res.render("errorMessage", { 
                error: "Not Authorized",
                title: "Error", }
            );
            return;
        }
  const users = await userCollection.find({}).toArray();
  users.forEach(user => {
    user._id = user._id.toString();
  });
  res.render("admin", { users, username: req.session.username, LoggedIn: req.session.authenticated,
    user_type: req.session.user_type,
   });
});




app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
        return;
    }

   


   res.render("members", {
  username: req.session.username,
  user_type: req.session.user_type,
    LoggedIn: req.session.authenticated,
});

});

app.post('/logout', (req, res) => {
    req.session.destroy();

    res.redirect('/');
});

app.get("*dummy", (req, res) => {
    res.status(404);
    res.render("404", {
        title: "Error",
        LoggedIn: req.session.authenticated,
        user_type: req.session.user_type
    });
})



app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 