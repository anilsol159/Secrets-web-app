import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";

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

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

async function registerUser(email,password){
  try{
    bcrypt.hash(password,saltRounds, async (err,hash) => {
      if(err){
        console.log(err);
      }else{
      await db.query("INSERT INTO users(email,password) VALUES($1,$2);",[email,hash]);
      }
    })
    
  }catch(err){
    console.log(err);
  }
}


app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  await registerUser(email,password);
  res.redirect("/");
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  var entry = null;
  
  try{
    entry = await db.query("SELECT password FROM users WHERE email = $1;",[email]);
    console.log(entry.rows.length);
  }catch(err){
    console.log(err);
  }
  if(entry.rows.length>0){
    const entryPassword = entry.rows[0].password;
    bcrypt.compare(password,entryPassword, (err,result) => {
      if(err){
        console.log(err);
      }else{
        if(result){
          res.render("secrets.ejs");
        }else{
          res.redirect("/login");
        }
      }
    })
  }else{
    res.redirect("/login");
  }
  
  
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
