const express= require("express");
const app = express();
require('dotenv').config();
app.use(express.json());
const dbserver= require("./config.js");
const UserRouter=require("./routes/userRoutes.js");

const PORT= process.env.PORT;

app.use("/fingerprint-auth",UserRouter);
// app.post('/fingerprint-auth', (req, res) => {
//     console.log('Fingerprint data received:', req.body);
//     res.json({ success: true, message: 'Fingerprint authenticated!' });
// });

app.listen(PORT,async()=>{
try{
    await dbserver();
    console.log(`${PORT} is running successfully`)
}catch(err){
    console.log(err.message);
}
})