const mongoose = require('mongoose');

const dbserver= async()=>{
    try{
        await mongoose.connect(process.env.DB_URL)
        console.log("db connected");
    }catch(err){
        console.log("failed to connect to db",err);
    }
}

module.exports= dbserver