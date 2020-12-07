const express = require('express');
const bodyParser = require('body-parser');
var cors = require('cors');
require('dotenv').config();

const app = express();
app.use(bodyParser.json({extended: false}));
app.use(cors());

app.post('/flag',async (req,res)=>{
    if (!req.body.name || typeof req.body.name !== 'string') {
        res.status(400).json({success: false, error: 'Invalid token'});
        res.end();
        return;
    }
    const name = req.body.name;
    var token = `{"admin":0,"name":"${name}"}`
    try{
        token = JSON.parse(token);
    }
    catch{
        res.json({success: false, error: 'Invalid token'});
        res.end();
        return;
    }
    if(token.admin === 1){
        res.json({success: true, flag: process.env.FLAG})
    }
    else{
        res.json({success: false, error: 'You are not admin'});
    }
})
app.listen(3000)