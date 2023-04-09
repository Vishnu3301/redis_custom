const express=require('express')
const app=express()
const uuid=require('uuid').v4
const {connectTodb,getClient}=require('./db')
const redis=require('redis')
const signature=require('cookie-signature')
const cookie=require('cookie')
const DeviceDetector=require('node-device-detector')
const onHeaders=require('on-headers')
const redisClient=redis.createClient()
let Session=require('./session')
let Cookie=require('./cookie')
const client=getClient()
const _db=client.db('auth_redis').collection('users')
const md5=require('md5')
app.use(express.json())
app.set('view engine','ejs')
app.use(express.urlencoded({extended:false}))
async function redisConnect(){
    await redisClient.connect()
}

const detector=new DeviceDetector({
    clientIndexes:true,
    deviceIndexes:true,
    deviceAliasCode:true,

})

const cookieOptions={
    //give the cookie options here
    secure:false,
    httpOnly:false,
    maxAge:500000
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
    console.log("new session created")
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

async function alreadyLoggedInAnotherDevice(req,userid){
    let data=await redisClient.get(userid)
    data=JSON.parse(data)
    if(data){
        console.log(data)
        return true
    }
    console.log(data)
    return false
}

//this function add req.session.user
app.use(async (req,res,next)=>{ 
    const cookieId= req.sessionID= getCookie(req,name,secret)
    if(cookieId){
        let data=await redisClient.get(cookieId);
        if(data){
            data=JSON.parse(data);
            req.session=new Session(req);
            req.session.user=data.user
        }

    }
    next();
})

app.get('/',(req,res)=>{
    const userAgent=req.headers['user-agent']
    console.log("md 5 has of user agent is: ",md5(userAgent))
    res.send("check conseole")
})

app.get('/login',(req,res)=>{
    if(req.session){
        if(req.session.user){
            return res.json({"user is already login ":req.session.user})
        }
        return res.render('login')
    }
    else{
        return res.render('login')
    }
})

app.post('/login',async (req,res)=>{
    const {username,password}=req.body;
    const hasuser=await _db.findOne({username:username})
    if(hasuser){
        const cookieId= req.sessionID= getCookie(req,name,secret)
        if(cookieId){
            let data=await redisClient.get(cookieId);
            if(data){
                //user has cookie id and a session already exists with that id  - means alredy logged in using other browser/device
                //delete the session data from session store related to previous login, then
                //create new session data
                await redisClient.del(cookieId)
                let userid=hasuser._id
                userid=userid.toString()
                const user={id:userid}
                const randomId=uuid()
                const SessionId=userid+':'+randomId
                generateSession(req,SessionId);
                req.session.user=user;
                await redisClient.del(cookieId) //delete the previous session from another device
                await redisClient.setEx(SessionId,60*10,JSON.stringify(req.session)) //set session data in redis store
                setcookie(res,name,SessionId,secret,req.session.cookie.data)
                return res.json( {"message":"Logging you in from this browser/device , logging you out from similar browser/ or from a  device, cookie sent with req"})
            }
            else{
                //user somehow has cookie id, but doesn;t have session data in redus store
                //may be the session data has expired
                //then user has to login again,
                //create session in session store,
                //set cookie
                let userid=hasuser._id
                userid=userid.toString()
                const user={id:userid}
                const randomId=uuid()
                const SessionId=userid+':'+randomId
                generateSession(req,SessionId);
                req.session.user=user;
                await redisClient.setEx(SessionId,60*10,JSON.stringify(req.session)) //set session data in redis store
                setcookie(res,name,SessionId,secret,req.session.cookie.data)
                return res.json({
                    "message":"logged in",
                })
            }
        }
        else{
            //cookie doesn't exists 
            let userid=hasuser._id
            userid=userid.toString()
            const existingSessionKeysObject=await redisClient.scan(0,{
                MATCH:`${userid}:*`,
                COUNT:1
            })
            if(existingSessionKeysObject.keys.length>0){
                const user={id:userid}
                const randomId=uuid()
                const posSessionId=userid+':'+randomId
                generateSession(req,posSessionId);
                req.session.user=user;
                await redisClient.del(existingSessionKeysObject.keys[0])
                await redisClient.setEx(posSessionId,60*10,JSON.stringify(req.session)) //set session data in redis store
                setcookie(res,name,posSessionId,secret,req.session.cookie.data)
                return res.json({
                    "message":"Logging you in from this browser/device , logging you out from similar browser/ or from a  device",
                })
            }
            else{
                //new login from a new where the user don't have any session data instore
                const user={id:userid}
                const randomId=uuid()
                const posSessionId=userid+':'+randomId
                generateSession(req,posSessionId);
                req.session.user=user;
                await redisClient.setEx(posSessionId,60*10,JSON.stringify(req.session)) //set session data in redis store
                setcookie(res,name,posSessionId,secret,req.session.cookie.data)
                return res.json({
                    "message":"logged in"
                })
            }
            
        }
    }
    else{
        return res.send("invalid creds")
    }
})

app.get('/somedata',async (req,res)=>{
    const keys=await redisClient.scan(0,{
        MATCH:"user:*",
        COUNT:1
    })
    res.send(keys)
})
app.get('/fav',(req,res)=>{
    if(req.session){
        if(req.session.user){
            return res.send(`logged in from this device ${req.session.user.id}`)
        }
    }
    return res.json("No session, login first")
})

app.get('/logout',async (req,res)=>{
    //del the session store key
    if(req.session){
        if(req.session.user){
            await redisClient.del(req.session.user.id)
            res.clearCookie(name)
            res.send("logged out")
        }
    }
    res.send("login first to  logout")
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