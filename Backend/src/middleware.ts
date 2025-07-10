import { Request , Response , NextFunction } from "express"
const JWT = require("jsonwebtoken")
const JWT_USER_PASSWORD = process.env.JWT_USER_PASSWORD

interface CustomRequest extends Request {
  userId?: string; // or `string | null` if needed
}

export async function userMiddlerware(req:CustomRequest , res:Response , next:NextFunction){
    const header = req.headers['authorization']
    const decoded = JWT.verify(header as  string , JWT_USER_PASSWORD)

    if(decoded){
        req.userId = decoded.id
        console.log(req.userId);
        
        next()
    }else{
        res.status(401).json({
            msg : "Unauthorzied user"
        })
    }
} 


// complete backend logic