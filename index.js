require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');

const Joi = require('joi');
const saltRounds = 12

const app = express(); 

const port = process.env.port || 3000; 

app.use(express.urlencoded({ extended: true})); 

app.use("/scripts", express.static("./Public/scripts"));
app.use("/styles", express.static("./Public/styles"));
app.use("/images", express.static("./Public/images"));

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = require('./connectionMongo');

const userCollection = database.db(mongodb_database).collection('users');

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	},
    ttl: 60 * 60
})

const expireTime = 1 * 60 * 60 * 1000;

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, 
	saveUninitialized: false, 
	resave: true,
    cookie: {maxAge: 60 * 60} 
}
));

app.get("/", (req, res) => {
    var placeholder = "";
    if (req.session.authenticated)
    {
        placeholder += `<p> Hi ` + req.session.username + ` </p>
        <form action="/members" method="get">
        <button>go to members</button>
      </form>
  
      <form action="/logout" method="post">
        <button>Logout</button>
      </form> `

    
    }
    else {
        placeholder += ` <form action="/createUser" method="get">
        <button>Sign Up</button>
      </form>
  
      <form action="/login" method="get">
        <button>Login</button>
      </form> `}
     
    res.send(placeholder);
});


app.get('/createUser', (req,res) => {
    if (req.session.authenticated == true) {
        res.redirect('/members');
    }

    var html = `
    create user
    <form action='/postUser' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
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

    const validationResult = schema.validate({username, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   var error = `<h1> Error: cannot make account </h1>
         <form action="/createUser" method="get">
        <button>go back to sign up?</button>
      </form>`
		res.send(error);
	   return;
   }

   var hashedPassword = await bcrypt.hash(password, saltRounds);

   await userCollection.insertOne({username: username, email: email, password: hashedPassword});
	console.log("Inserted user");

    req.session.authenticated = true;
		req.session.username = username;
		req.session.cookie.maxAge = expireTime;

        res.redirect('/members');

});

app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/loggingin', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

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
        res.redirect('/members')
		return;
	}
	else {
		console.log("incorrect password");
		res.redirect("/login");
		return;
	}
});





app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }

    if (!req.query.id) {
        var image = Math.floor(Math.random() * 3) + 1;

        return res.redirect(`/members?id=${image}`);
    }
    
    var username = req.session.username;
    let imgnum = parseInt(req.query.id);
    
    var page = `<h1> Welcome `+ username +` ! </h1>`;

    if (imgnum === 1) {
        page += `<br> <img src="/images/cat1.jpg" /> `;
    }
    if (imgnum === 2) {
        page += `<br> <img src="/images/cat2.jpg" /> `;
    }
    if (imgnum === 3) {
        page += `<br> <img src="/images/cat3.jpg" /> `;
    }
    page += `<br> <form action="/logout" method="POST"> 
    <button> logout </button> </form> `;
    res.send(page);

});

app.post('/logout', (req,res) => {
	req.session.destroy();
   
    res.redirect('/');
});

app.get("*dummy", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})



app.listen(port, () => {
	console.log("Node application listening on port "+ port);
}); 