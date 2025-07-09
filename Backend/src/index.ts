import express from "express"
import { Application,Request, Response } from "express";
// express code
const app: Application = express();
app.use(express.json());

//zod code
import z, { boolean, ParseStatus } from "zod"

// .env code
import dotenv from "dotenv";
dotenv.config()

//JWT
const JWT = require("jsonwebtoken")
const JWT_USER_PASSWORD = process.env.JWT_USER_PASSWORD

//mongoose code
import mongoose from "mongoose"
const MONGO_URL : string = process.env.MONGO_URL || "undefined";

const {userModel} = require('./db')
// const {contentModel} = require('./db')


//bcrypt
const bcrypt = require("bcrypt")

interface CustomRequest extends Request {
  userId?: string; // or `string | null` if needed
}


const userProfileSchema = z.object({
    firstName: z.string().min(1),
    password: z
        .string()
        .min(8, "Password must be at least 8 characters")
        .max(20, "Password must be at most 20 characters")
        .regex(
            /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,20}$/,
            "Password must include uppercase, lowercase, number, and symbol"
        )
});


//-------------------Sign-UP---------------------------------------------------

app.post('/api/v1/signup', async function (req : Request, res : Response) {
    const { success,error } = userProfileSchema.safeParse(req.body);

    if (!success) {
          res.status(411).json({
            msg: "Error in inputs",
            errors: error.errors 
        });
        return 
    }
    
    const {email , password , firstName , lastName} = req.body;
    const hashedPassword = await bcrypt.hash(password,5);  
    try {
        await userModel.create({
            email,
            password : hashedPassword,
            firstName,
            lastName
        });
    }
    catch(e){
        res.status(403).json({
            msg : "user already exists"
        })
        return
    }

    res.status(200).json({
        msg : "Signed up Success"
    })

})