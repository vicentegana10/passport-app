const express = require(`express`)
const app = express()
app.set(`view engine`, `ejs`);


const session = require(`express-session`)
const passport = require(`passport`)
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require( `passport-google-oauth2` ).Strategy;
// Get rest-pg file from the same folder in a const called db
const db = require(`./rest-pg`)


//Middleware
app.use(session({
    secret: `secret`,
    resave: false ,
    saveUninitialized: true ,
}));

app.use(passport.initialize()) // init passport on every route call
app.use(passport.session())    //allow passport to use `express-session`


//Get the GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET from Google Developer Console
const dotenv = require(`dotenv`)
dotenv.config()

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET

authUser = (request, accessToken, refreshToken, profile, done) => {
    return done(null, profile);
  }

//Use `GoogleStrategy` as the Authentication Strategy
passport.use(new GoogleStrategy({
    clientID:     GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: `http://localhost:3000/auth/google/callback`,
    passReqToCallback   : true
  }, authUser));

// Define la estrategia local de Passport
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const query = 'SELECT * FROM users WHERE username = $1';
      const values = [username];
      const { rows } = await db.query(query, values);

      if (rows.length > 0) {
        const user = rows[0];

        if (password === user.password) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect username or password' });
        }
      } else {
        return done(null, false, { message: 'User not found' });
      }
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser( (user, done) => { 
    console.log(`\n--------> Serialize User:`)
    console.log(user)
     // The USER object is the `authenticated user` from the done() in authUser function.
     // serializeUser() will attach this user to `req.session.passport.user.{user}`, so that it is tied to the session object for each session.  

    done(null, user.id)
} )


passport.deserializeUser(async (id, done) => {
  try {
    const query = 'SELECT * FROM users WHERE id = $1';
    const values = [id];
    const { rows } = await db.query(query, values);

    if (rows.length > 0) {
      const user = rows[0];
      done(null, user);
    } else {
      done(null, false, { message: 'User not found' });
    }
  } catch (err) {
    done(err);
  }
});


//Start the NODE JS server
app.listen(3000, () => console.log(`Server started on port 3000`))


//console.log() values of `req.session` and `req.user` so we can see what is happening during Google Authentication
let count = 1
showlogs = (req, res, next) => {
    console.log(`\n==============================`)
    console.log(`------------>  ${count++}`)

    console.log(`\n req.session.passport -------> `)
    console.log(req.session.passport)
  
    console.log(`\n req.user -------> `) 
    console.log(req.user) 
  
    console.log(`\n Session and Cookie`)
    console.log(`req.session.id -------> ${req.session.id}`) 
    console.log(`req.session.cookie -------> `) 
    console.log(req.session.cookie) 
  
    console.log(`===========================================\n`)

    next()
}

app.use(showlogs)

// Ruta para el formulario de registro local
app.get('/register', (req, res) => {
  res.render('register.ejs');
});

// Ruta para procesar la solicitud de registro local
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const query = 'INSERT INTO users (username, password) VALUES ($1, $2)';
    const values = [username, password];
    await db.query(query, values);
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.redirect('/register');
  }
});



app.get(`/auth/google`,
  passport.authenticate(`google`, { scope:
      [ `email`, `profile` ] }
));

app.get(`/auth/google/callback`,
    passport.authenticate( `google`, {
        successRedirect: `/dashboard`,
        failureRedirect: `/login`
}));

//Define the Login Route
app.get(`/login`, (req, res) => {
    res.render(`login.ejs`)
})

// Ruta para procesar la solicitud de inicio de sesión local
app.post('/login', passport.authenticate('local', {
  successRedirect: '/dashboard',
  failureRedirect: '/login',
}));


//Use the req.isAuthenticated() function to check if user is Authenticated
checkAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) { return next() }
  res.redirect(`/login`)
}

//Define the Protected Route, by using the `checkAuthenticated` function defined above as middleware
app.get(`/dashboard`, checkAuthenticated, (req, res) => {
  res.render(`dashboard.ejs`, {name: req.user.displayName})
})

//Define the Logout
app.post(`/logout`, (req, res) => {
  req.logout(function (err) {
      if (err) {
          console.log(err);
      }
      res.redirect(`/login`);
      console.log(`-------> User Logged out`);
  });
});
