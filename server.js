import express from 'express'
import cookieParser from 'cookie-parser'
import flash from 'express-flash'
import session from 'express-session'
import passport from 'passport'
import { Strategy as LocalStrategy } from 'passport-local'
import conn from './database-conn.js'
import dotenv from 'dotenv'
import path from 'path'
import bcrypt from 'bcrypt'
import cors from 'cors'
import bodyParser from 'body-parser'
const app = express()
const moduleURL = new URL(import.meta.url)
const __dirname = path.dirname(moduleURL.pathname)
app.use('/static', express.static(path.join(__dirname, 'public'))) // Public folder where images will be stored
app.use(bodyParser.json()) // in POST requests we need to see req.body
app.use(express.urlencoded({ extended: false }));
// CORS
app.use(cors())
app.options("*", cors())
// END CORS
// Session 
const d = new Date();
// Session middleware
// maxAge: d.setTime(d.getTime() + 24 * 60 * 60 * 1000) // 24hours
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 2 * 60 * 60 * 1000
  }
}));
// Passport Authentication
app.use(passport.initialize());
app.use(passport.session());
passport.use('local', new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true,
    session: {
      maxAge: 30 * 1000 // 30 seconds for testing, align with express-session maxAge
    }
  } , function (req, username, password, done){
        if(!username || !password ) {
            return done(null, false, req.flash('message','All fields are required.'));
        }
        conn.query("select * from users where email = ?", [username], function(err, rows){
            const dbpwd = rows[0].pwd.toString();
            if (err) return done(req.flash('error message: ',err));
            if ((!rows.length) || (!bcrypt.compareSync(password.toString(), rows[0].pwd.toString()))) {
              return done(null, false, { statusCode: 404, message: "Adresse éléctronique ou mot de passe n'est pas invalide." });
            }else{
                return done(null, rows[0]);
            }
        })
    }
));
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      try {
        const serializedUser = { id: user.id, useremail: user.email, admin:user.admin };
        console.log("in SERialise")
        console.log(serializedUser)
        cb(null, serializedUser);
      } catch (err) {
        cb(err); // Pass the error to cb
      }
    });
});
passport.deserializeUser(function(serializedUser, cb) {
    const userId = serializedUser.id;
    conn.query("SELECT * FROM users WHERE id = ?", [userId], function(err, rows) {
      if (err) {
        return cb(err);
      }
  
      if (rows.length === 0) {
        console.log("User not found");
        return cb(null, false);
      }
  
      const user = rows[0];
      cb(null, user);
    });
});
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.status(401).json({ error: 'Unauthorized' });
} 
// END Password
app.post("/login", function(req, res, next) {
    passport.authenticate('local', function(err, user, info) {
      if (err) {
        console.error("Passport authentication error:", err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      if (user) {
        req.login(user, function(err) {
          if (err) {
            console.error("Passport login error:", err);
            return res.status(500).json({ error: 'Internal Server Error' });
          }
          // Set a cookie
          res.cookie('token_from_passport', req.sessionID, {
            secure: false,    // Ensure the cookie is only transmitted over HTTPS
            httpOnly: false,  // Restrict access to the cookie from client-side JavaScript
          });
          res.status(200).json({ authToken: process.env.AUTH_TOKEN, success: true });

        });
      } else {
        const statusCode = info && info.statusCode ? info.statusCode : 401;
        const message = info && info.message ? info.message : 'Unauthorized';
        return res.status(statusCode).json({ error: message });
      }
    })(req, res, next);
});
app.post('/create', (req,res,next)=>{
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    const hashedPassword = bcrypt.hashSync(password, 10);
    conn.query("insert into users values(?,?,?,?,?)", [null, req.body.username, bcrypt.hashSync(req.body.password, 10), true, null], function(error, result){
        if (error) {
            console.error('Error inserting user:', error);
            return res.status(500).json({ error: 'Internal Server Error' });
        }
        return res.status(201).json({ success: true }); 
    })
})









app.post('/logout', function(req, res, next) {
    req.logout(function(err) {
      if (err) { return next(err); }
      console.log("Log out success")
      return res.status(201).json({ success: true }); 
    });
});
app.listen(4000,()=>{console.log("Server started")})