// ----------------- VARIABLES DE ENTORNO ----------------------------
const dotenv = require(`dotenv`)
dotenv.config()
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET
//------------------ FIN DE LAS VARIABLES DE ENTORNO -----------------


//-------- NECESARIO PARA EL FUNCIONAMIENTO DE LA APLICACION --------
const express = require(`express`)
const session = require(`express-session`)
const app = express()
app.set(`view engine`, `ejs`);
//------------------ FIN DE LO NECESARIO ----------------------------


//------------------ MIDLEWARES -------------------------------------
app.use(session({
  secret: `secret`,
  resave: false ,
  saveUninitialized: true ,
}));
//------------------ FIN DE LOS MIDLEWARES ---------------------------


// --------------- FUNCIONES DE AUTENTICACION ------------------------
authUser = (request, accessToken, refreshToken, profile, done) => {
  return done(null, profile);
}

checkAuthenticated = (req, res, next) => {
if (req.isAuthenticated()) { return next() }
res.redirect(`/login`)
}
//------------------ FIN DE LAS FUNCIONES DE AUTENTICACION -----------


//-------- NECESARIO PARA EL FUNCIONAMIENTO DE PASSPORT --------------
const passport = require(`passport`)
const LocalStrategy = require(`passport-local`).Strategy;
const GoogleStrategy = require( `passport-google-oauth2` ).Strategy;
app.use(passport.initialize())
app.use(passport.session())

// Serializar y deserializar usuarios
passport.serializeUser( (user, done) => { 
  console.log(`\n--------> Serialize User:`)
  console.log(user)
  done(null, user.id)
} )

passport.deserializeUser(async (id, done) => {
try {
  const query = `SELECT * FROM users WHERE id = $1`;
  const values = [id];
  const { rows } = await pool.query(query, values);

  if (rows.length > 0) {
    const user = rows[0];
    done(null, user);
  } else {
    done(null, false, { message: `User not found` });
  }
} catch (err) {
  done(err);
}
});

// Estrategia de Google de Passport
passport.use(new GoogleStrategy({
  clientID:     GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: `http://localhost:3000/auth/google/callback`,
  passReqToCallback   : true
}, authUser));

// Estrategia local de Passport
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const query = `SELECT * FROM users WHERE username = $1`;
      const values = [username];
      const { rows } = await pool.query(query, values); 

      if (rows.length > 0) {
        const user = rows[0];

        if (password === user.password) {
          return done(null, user);
        } else {
          return done(null, false, { message: `Incorrect username or password` });
        }
      } else {
        return done(null, false, { message: `User not found` });
      }
    } catch (err) {
      return done(err);
    }
  }
));
//------------------ FIN DE LO NECESARIO ----------------------------


//-------- NECESARIO PARA EL FUNCIONAMIENTO DE LA BASE DE DATOS ------
const { Pool } = require(`pg`);
const pool = new Pool({connectionString: 'postgres://root:root@postgres:5432/root'});
//------------------ FIN DE LO NECESARIO ----------------------------


// ----------------- SERVIDOR ----------------------------------------
app.use(express.urlencoded({ extended: true }));
app.listen(3000, () => console.log(`Server started on port 3000`))
//------------------ FIN DEL SERVIDOR -------------------------------


// ---------------- REGISTRO DE USUARIOS ----------------------------
app.get(`/register`, (req, res) => {
  res.render(`register.ejs`);
});

// Registro local
app.post(`/register`, async (req, res) => {
  const { username, password } = req.body;
  try {
    const query = `INSERT INTO users (username, password) VALUES ($1, $2)`;
    const values = [username, password];
    await pool.query(query, values);
    res.redirect(`/login`);
  } catch (err) {
    console.error(`Error al registrar el usuario`, err);
    res.redirect(`/register`);
  }
});

// Registro de Google
app.get(`/auth/google`,
  passport.authenticate(`google`, { scope:
      [ `email`, `profile` ] }
));
app.get(`/auth/google/callback`,
    passport.authenticate( `google`, {
        successRedirect: `/dashboard`,
        failureRedirect: `/login`
}));
// ---------------- FIN DEL REGISTRO DE USUARIOS ---------------------


// ---------------- INICIO DE SESION --------------------------------
app.get(`/login`, (req, res) => {
    res.render(`login.ejs`)
})

// Ruta para procesar la solicitud de inicio de sesión local
app.post(`/login`, passport.authenticate(`local`, {
  successRedirect: `/dashboard`,
  failureRedirect: `/login`,
}));
// ---------------- FIN DEL INICIO DE SESION -------------------------


// ----------------- RUTAS PROTEGIDAS --------------------------------
app.get(`/dashboard`, checkAuthenticated, (req, res) => {
  res.render(`dashboard.ejs`, {name: req.user.displayName})
})
// ----------------- FIN DE LAS RUTAS PROTEGIDAS ---------------------


// ----------------- CERRAR SESION -----------------------------------
app.post(`/logout`, (req, res) => {
  req.logout(function (err) {
      if (err) {
          console.log(err);
      }
      res.redirect(`/login`);
      console.log(`-------> User Logged out`);
  });
});
// ----------------- FIN DE CERRAR SESION -----------------------------


// ----------------- OTROS --------------------------------------------
/*
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
*/
// ----------------- FIN DE OTROS -------------------------------------