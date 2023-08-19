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
import nodemailer from 'nodemailer'
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
    maxAge: 3 * 60 * 60 * 1000
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
      maxAge: 7200000 // 30 seconds for testing, align with express-session maxAge
    }
  } , function (req, username, password, done){
        if(!username || !password ) {
            return done(null, false, req.flash('message','All fields are required.'));
        }
        conn.query("select * from users where email = ?", [username], function(err, rows){
            if (err) return done(req.flash('error message: ',err));
            if ((!rows.length) || (!bcrypt.compareSync(password.toString(), rows[0].pwd.toString()))) {
              return done(null, false, { statusCode: 401, message: "Wrong credentials" });
            }else if(!rows[0].verified){
              return done(null, false, { statusCode: 401, message: "Please check your email to validate your signup" });
            }
            else{
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
          res.status(200).json({ username: user.username, success: true });

        });
      } else {
        const statusCode = info && info.statusCode ? info.statusCode : 401;
        const message = info && info.message ? info.message : 'Unauthorized';
        return res.status(statusCode).json({ error: message });
      }
    })(req, res, next);
});
/*********** SIGN UP *********/
function generateRandomToken() {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < 32; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    token += characters[randomIndex];
  }
  const expirationTime = Date.now() + 24 * 60 * 60 * 1000;
  const obj ={
    token: token,
    expirationTime: expirationTime
  }
  return obj;
}
/*
app.post('/signup', async (req, res, next) => {
    const { username, email, password } = req.body;
    
    if (!username || !password || !email) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const [userCheckResult] = await conn.promise().query("select * from users where email = ?;", [req.body.email]);
        
        if (userCheckResult.length) {
            return res.status(200).json({ message: "User exists in the database." });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);
        const insertUserResult = await conn.promise().query("insert into users values(?,?,?,?,?,?,?)", [null, req.body.email, req.body.username, bcrypt.hashSync(req.body.password, 10), true, false, null]);

        const tokenExpiration = generateRandomToken();
        const token = bcrypt.hashSync(tokenExpiration.token, 10);
        const expirationTime = tokenExpiration.expirationTime;
        
        const expirationTimeAsDate = new Date(expirationTime);

        const insertVerifyResult = await conn.promise().query("insert into users_verify values(?,?,?,?,?,?);", [null, insertUserResult.insertId, token, expirationTime, null, null]);

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.GMAIL,
                pass: process.env.GMAILPWD
            }
        });

        const mailOptions = {
            from: process.env.GMAIL,
            to: req.body.email,
            subject: 'Signup Validation',
            html: `
                <h2>Signup Validation</h2>
                <p>Hello, <strong>${req.body.username}</strong></p>
                <p>Please click this <a href="http://localhost:4000/validate?token=${tokenExpiration.token}">link</a> to validate your signup</p>
                <p>The link expires in 24 hours, it's valid until <strong>${expirationTimeAsDate}</strong></p>
            `,
        };

        await transporter.sendMail(mailOptions);
        console.log('Email sent');

        return res.status(200).json({ message: "Check your email to validate the signup" });
    } catch (error) {
        console.error('Error during signup:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});
*/
app.post('/signup', (req,res,next)=>{
    const { username, email, password } = req.body;
    if (!username || !password || !email) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    conn.query("select * from users where email = ?;", [req.body.email], function(error, result){
      if(error){
        console.error('Error verifying user:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
      }if(result.length){
        return res.status(200).json({ message: "User exists in the database." });
      }else{
        const hashedPassword = bcrypt.hashSync(password, 10);
        conn.query("insert into users values(?,?,?,?,?,?,?)", [null, req.body.email, req.body.username, bcrypt.hashSync(req.body.password, 10), true, false, null], function(error, result){
            if (error) {
                console.error('Error inserting user:', error);
                return res.status(500).json({ error: 'Internal Server Error' });
            }else{
              const tokenExpiration = generateRandomToken()
              const token = bcrypt.hashSync(tokenExpiration.token, 10);
              const expirationTime = tokenExpiration.expirationTime;
              const expirationTimeAsDate = new Date(expirationTime)
              conn.query("insert into users_verify values(?,?,?,?,?,?);", [null, result.insertId, token, expirationTime, null, null], function(err, validateResult){
                if(err){
                  console.error('Error inserting user verify data:', error);
                  return res.status(500).json({ error: 'Internal Server Error' });
                }else{
                  async function sendValidationToken(){
                    const transporter = nodemailer.createTransport({
                      service: 'gmail',
                      auth: {
                        user: process.env.GMAIL,
                        pass: process.env.GMAILPWD
                      }
                    });
                    const mailOptions = {
                      from: process.env.GMAIL,
                      to: req.body.email,
                      subject: 'Signup Validation',
                      html: `
                        <h2>Signup Validation</h2>
                        <p>Hello, <strong>${req.body.username}</strong></p>
                        <p>Please click this <a href="http://localhost:4000/validate?token=${tokenExpiration.token}&user_id=${result.insertId}">link</a> to validate your signup</p>
                        <p>The link expires in 24 hours, it's valid until <strong>${expirationTimeAsDate}</strong></p>
                      `,
                    };

                    try {
                      await transporter.sendMail(mailOptions);
                      console.log('Email sent');
                      /*
                      res.status(200).json({
                        status: "success",
                        message: "Enquiry submitted successfully",
                      });
                      */
                    } catch (error) {
                      console.error('Error sending email:', error);
                      //res.status(500).end();
                    }
                  }
                  sendValidationToken();
                  return res.status(200).json({ message: "Check your email to validate the signup" });
                }
              })
            } 
        })
      }
    })
})
app.get("/validate", (req,res)=>{
  conn.query("select * from users u cross join users_verify uv on u.id = uv.user_id where u.id = ?;", [req.query.user_id], function(error, result){
    if(error)return res.status(500).json({ error: 'Internal Server Error' });
    if(!result.length){
      res.send("No user were detected please register")
    }else{
      if(result[0].verified)res.redirect("http://localhost:3000");
      else{
          if(bcrypt.compareSync(req.query.token.toString(), result[0].verify_token.toString())){
            if(result[0].verify_token_expirationn >= now){
              conn.query("update users set verified = true where id = ?;", [req.query.user_id], function(err,responseFromDb){
                if(err){
                  console.log(err);
                  return res.status(500).json({ error: 'Internal Server Error' });
                }else{
                  res.redirect("http://localhost:3000")
                }
              })
            }else{
              res.send("Your token has expired. Get a new token")
            }
          }else{
            res.send("The link is wrong, please register")
        }
      }
    }
  })
})
/*
if(!result.length){
          res.send("No user were detected please register")
        }else{
          const now = new Date().getTime()
          if(bcrypt.compareSync(req.query.token.toString(), result[0].verify_token.toString()) && result[0].verify_token_expirationn >= now){
            conn.query("update users set verified = true where id = ?;", [req.query.user_id], function(err,responseFromDb){
              if(err){
                console.log(err);
                return res.status(500).json({ error: 'Internal Server Error' });
              }else{
                res.redirect("http://localhost:3000")
              }
            })
          }else if(bcrypt.compareSync(req.query.token.toString(), result[0].verify_token.toString()) && result[0].verify_token_expirationn < now){
            res.send("Your token has expired. Get a new token here")
          }else if(!bcrypt.compareSync(req.query.token.toString(), result[0].verify_token.toString())){
            res.send("The link is wrong, please register")
          } 
        }
*/
/********** END SIGNUP ***********/






app.post('/logout', function(req, res, next) {
    req.logout(function(err) {
      if (err) { return next(err); }
      console.log("Log out success")
      return res.status(201).json({ success: true }); 
    });
});
app.listen(4000,()=>{console.log("Server started")})
/*
// Passport 19th of Agust
passport.use('local', new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true,
    session: {
      maxAge: 7200000 // 30 seconds for testing, align with express-session maxAge
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
 */