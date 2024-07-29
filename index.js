import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";

const app = express();
const port = 3000;
const saltRounds = 10;

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "Raaz1",
  password: "AnilKeRaaz",
  port: 5432,
});
db.connect()

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: "MereRaaz",
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
  }
}));

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/secrets",(req,res) => {
  if(req.isAuthenticated()){
    res.render("secrets.ejs");
  }else{
    res.redirect("/");
  }
})

app.get("/register", (req, res) => {
  res.render("register.ejs");
});



app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  try{
    bcrypt.hash(password,saltRounds, async (err,hash) => {
      if(err){
        console.log(err);
      }else{
      const result = await db.query("INSERT INTO users(email,password) VALUES($1,$2) RETURNING *;",[email,hash]);
      const user = result.rows[0];
      req.login(user,(err) => {
        res.redirect("/secrets")
      })
      }
    })
    
  }catch(err){
    console.log(err);
  }
});

app.post("/login", passport.authenticate("local",{
  successRedirect : "/secrets",
  failureRedirect: "/login"
}));

passport.use(new Strategy(async function verify(username,password,cb){
  var entry = null;
  
  try{
    entry = await db.query("SELECT password FROM users WHERE email = $1;",[username]);
    console.log(entry.rows.length);
  }catch(err){
    return cb(err);
    
  }
  if(entry.rows.length>0){
    const user = entry.rows[0];
    const entryPassword = entry.rows[0].password;
    bcrypt.compare(password,entryPassword, (err,result) => {
      if(err){
        return cb(err);
      }else{
        if(result){
          return cb(null,user);
          
        }else{
          return cb(null,false);
        }
      }
    })
  }else{
    return cb("User not found")
  }
}))

passport.serializeUser((user,cb) => {
  cb(null,user);
})

passport.deserializeUser((user,cb) => {
  cb(null,user);
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
