const express=require('express')
const app=express()
const uuid=require('uuid').v4
const {connectTodb,getClient}=require('./db')
const redis=require('redis')
const signature=require('cookie-signature')
const cookie=require('cookie')
const redisClient=redis.createClient()
let Session=require('./session')
let Cookie=require('./cookie')
const client=getClient()
const _db=client.db('auth_redis').collection('users')
const { ObjectId } = require('mongodb')
app.use(express.json())
app.set('view engine','ejs')
app.use(express.urlencoded({extended:false}))
async function redisConnect(){
    await redisClient.connect()
}

const cookieOptions={
    //give the cookie options here
    secure:false,
    httpOnly:false,
    maxAge:500000,
}


const opts={
    //set session options here
    name:"sscok",
    secret:"notsosecret"
}

function generateSession(req,sessionId){
    req.sessionID=sessionId;
    req.session=new Session(req);
    req.session.cookie=new Cookie(cookieOptions)
    // console.log("new session created")
}

const name=  opts.name || 'connect.sid'

const secret=opts.secret

function setcookie(res,name,val,secret,options){
    //code is from the source code of express-session
    let signed = 's:' + signature.sign(val, secret);
    let data = cookie.serialize(name, signed, options);
    
    let prev = res.getHeader('Set-Cookie') || []
    let header = Array.isArray(prev) ? prev.concat(data) : [prev, data];
    
    res.setHeader('Set-Cookie', header)
}


function getCookie(req,name,secret){
    let header=req.headers.cookie
    let raw,val

    if(header){
        let cookies=cookie.parse(header)
        raw =cookies[name]

        if (raw){
            if(raw.substring(0,2)==='s:'){
                val=unsigncookie(raw.slice(2),secret)
                if(val===false){
                    val=undefined
                }
            }
        }
    }
    return val
}

function unsigncookie(val, secret) {
    var result = signature.unsign(val, secret);
    
    if (result !== false) {
        return result;
    }
    
    return false;
}


//this function is to add user object to req.session if session exists
app.use(async (req,res,next)=>{ 
    const cookieId= req.sessionID= getCookie(req,name,secret)
    // console.log("running middlwar");
    // console.log("cookie id: ",cookieId)
    if(cookieId){
        let data=await redisClient.get(cookieId);
        if(data){
            data=JSON.parse(data);
            req.session=new Session(req);
            req.session.user=data.user
            // console.log(req.session.user)
        }

    }
    next();
})


app.get('/login',(req,res)=>{
    if(req.session){
        if(req.session.user){
            return res.json({message:"user is already logged in"})
        }
        return res.render('login')
    }
    else{
        return res.render('login')
    }
})

app.post('/login',async (req,res)=>{
    const {username,password}=req.body;
    //not real authentication
    const hasuser=await _db.findOne({username:username,password:password})
    if(hasuser){
        //get the cookie id
        // const cookieId= req.sessionID= getCookie(req,name,secret)
        let userid=hasuser._id
        userid=userid.toString()
        const user={id:userid}
        const existingSessionKeysObject=await redisClient.scan(0,{
            MATCH:`${userid}:*`,
            COUNT:1
        })
        if(existingSessionKeysObject.keys.length>0){
            //this means user has already logged in from another device/ browser on the same device
            //delete the existing user session
            //create new session and login
            const randomId=uuid()
            const SessionId=userid+':'+randomId
            generateSession(req,SessionId);
            req.session.user=user;
            await redisClient.del(existingSessionKeysObject.keys[0]) //delete the previous session from another device
            await redisClient.setEx(SessionId,60*10,JSON.stringify(req.session)) //set session data in redis store
            setcookie(res,name,SessionId,secret,req.session.cookie.data)
            return res.json( {"message":"Logged out from one device, logged in from this"})
        }
        else{
            //no previous session data exists
            //create a login
            const randomId=uuid()
            const SessionId=userid+':'+randomId
            generateSession(req,SessionId);
            req.session.user=user;
            await redisClient.setEx(SessionId,60*10,JSON.stringify(req.session)) //set session data in redis store
            setcookie(res,name,SessionId,secret,req.session.cookie.data)
            return res.json({
                "message":"Logged in, previous session doesn't exist",
            })
        }
    }
    else{
        return res.send("invalid creds")
    }
})


app.get('/fav',async (req,res)=>{
    if(req.session){
        if(req.session.user){
            let userid=new ObjectId(req.session.user.id)
            const fav=await _db.findOne({_id:userid});
            return res.json({fav:fav})
        }
    }
    return res.json("Login First")
})

app.get('/logout',async (req,res)=>{
    //del the session store key
    if(req.session){
        if(req.session.user){
            const cookieId=getCookie(req,name,secret)
            await redisClient.del(cookieId)
            res.clearCookie(name)
            return res.send("logged out")
        }
    }
    return res.send("login first to  logout")
})

connectTodb()
.then(()=>{
    console.log("mongodb connected")
    redisConnect()
    .then(()=>{
        console.log("redis connected")
        app.listen(3000,()=>{
            console.log("listening on port 3000")
        })
    })

})