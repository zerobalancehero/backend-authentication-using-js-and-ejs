require("dotenv").config()
const cookieparser=require("cookie-parser")
const express=require("express")
const jwt=require("jsonwebtoken")
const bcrypt=require("bcrypt")
const db= require("better-sqlite3")("ourApp.db")
db.pragma("journal_mode=WAL")

//database setup 
const createTables=db.transaction(()=>{
  db.prepare(`
    CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL
    )
    `).run()
})

createTables()

const app=express()

app.set("view engine","ejs")
app.use(express.urlencoded({extended:false}))
app.use(express.static("public"))
app.use (cookieparser())


app.use(function(req,res,next){
  res.locals.errors=[]
  //try to decode incoming cookie
  try{
    const decode=jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
    req.user=decode

    const issuedAt = new Date(decode.iat * 1000).toString();
    console.log("Token issued at:", issuedAt);
  }catch(err){
    req.user=false
  }

  res.locals.users=req.user
  console.log(req.user)
   
  next()
})

app.get("/",(req,res)=>{
  res.render("homepage")
})

app.get("/login",(req,res)=>{
  res.render("login")
})

app.post("/register",(req,res)=>{
const errors=[]
 if(typeof req.body.username!=="string") req.body.username="";
 if(typeof req.body.password!=="string") req.body.password="";
 req.body.username = req.body.username.trim()

 if(!req.body.username) errors.push("You must provide a username")
  if(req.body.username && req.body.username.length<3) errors.push("username must be atleast 8 characters long")
  if(req.body.username && req.body.username.length>10) errors.push("username cannot exceed 10 characters")
  if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("username can only contain letters and numbers")
  

    if(!req.body.password) errors.push("You must provide a password")
  if(req.body.password && req.body.password.length<3) errors.push("password must be atleast 12 characters long")
  if(req.body.password && req.body.password.length>10) errors.push("password cannot exceed 17 characters")
  if(errors.length){
    return res.render("homepage",{errors})
  }
  //save the new user into a database
  const ourStatement=db.prepare("INSERT INTO users (username,password) VALUES (?,?)")
  const result=ourStatement.run(req.body.username,req.body.password)
  
  const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID =? ")
  const ourUser=lookupStatement.get(result.lastInsertRowid)

  //log the user in by giving cookie to user

  const TokenValue=jwt.sign({exp: Math.floor(Date.now()/1000)+60*60*24,userid:ourUser.id,username:ourUser.username} ,process.env.JWT )

 

  res.cookie("ourSimpleApp",TokenValue,{
    httpOnly:true,
    secure:true,
    sameSite:"strict",
    maxAge:1000*60*60*24
  })

  res.send("Thank you ")
})

app.listen(3000)