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
import { userMiddlerware } from "./middleware";
const MONGO_URL : string = process.env.MONGO_URL || "undefined";

const {userModel,contentModel,linkModel} = require('./db')
// const {contentModel} = require('./db')
import { random } from "./utlis";

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


//-------------------Sign-IN---------------------------------------------------


app.put('/api/v1/signin',async (req : Request, res : Response) => {
    const { email , password } = req.body;
    const user = await userModel.findOne({
        email : email,
    })

    if(!user){
        res.status(403).json({
            msg : "User doesn't exist or wrong credentials"
        })
        return
    }

    const passwordMatch : boolean = await bcrypt.compare(password , user.password);
    if(passwordMatch){
        const token = JWT.sign({
            id : user._id
        },JWT_USER_PASSWORD);

        res.status(200).json({
            msg : "Signed-up Success",
            token : token
        })
        return
    }
    else{
        res.status(403).json({
            msg : "Invail Credentials"
        })
    }

})


//-------------------Add content---------------------------------------------------


app.post('/api/v1/content',userMiddlerware,async (req:CustomRequest, res:Response) => {
    const { link, type, title } = req.body;
    // Create a new content entry linked to the logged-in user.
    await contentModel.create({
        link,
        // type,
        title,
        userId: req.userId, // userId is added by the middleware.
        // tags: [] // Initialize tags as an empty array.
    });

    res.json({ message: "Content added" }); 
})

//-------------------Get user content---------------------------------------------------


app.get("/api/v1/content", userMiddlerware, async (req, res) => {
    //@ts-ignore
    const userId = req.userId;  // User ID is fetched from middleware
    // Fetch all content associated with the user ID and populate username
    // The `populate` function is used to include additional details from the referenced `userId`.
    // For example, it will fetch the username linked to the userId.
    // Since we specified "username", only the username will be included in the result, 
    // and other details like password won’t be fetched.
    const content = await contentModel.find({ userId: userId }).populate("userId", "username");
    res.json(content);  // Send the content as response
});

//-------------------Delete---------------------------------------------------------------

app.delete('/api/v1/content', userMiddlerware, async (req: CustomRequest, res: Response) => {
  try {
    const contentId = req.body.contentId;

    if (!contentId || !mongoose.Types.ObjectId.isValid(contentId)) {
      res.status(400).json({ msg: "Invalid or missing contentId" });
      return
    }

    const result = await contentModel.deleteOne({
      _id: contentId,
      userId: req.userId
    });

    if (result.deletedCount === 0) {
      res.status(404).json({ msg: "No content found or unauthorized" });
      return
    }

    res.status(200).json({ msg: "Deleted successfully" });

  } catch (error) {
    console.error("Error deleting content:", error);
    res.status(500).json({ msg: "Server error" });
  }
});

//-------------------Share content--------------------------------------------------
app.post('/api/v1/brain/share',userMiddlerware,async (req : CustomRequest, res:Response) => {
    const {share} = req.body

    if(share){
        const existingLink = await linkModel.findOne({userId : req.userId});
        if(existingLink){
            res.json({
                hash : existingLink.hash
            })
            return
        }
        
        //Generate a shareable link
        const hash = random(20);
        await linkModel.create({
            userId : req.userId,
            hash
        })
    }
    // else logic is to delete the shareable link
    else{
        await linkModel.deleteOne({
            userId : req.userId
        })
        res.json({
            msg : "link deactivated"
        })
    }
})

app.get('/api/v1/brain/:shareLink',async (req : CustomRequest, res:Response) => {
    const hash = req.params.shareLink;
    const link = await linkModel.findOne({hash});
    if(!link){
        res.status(404).json({
            msg : " If the share link is invalid or sharing is disabled"
        })
        return
    }
    const content = await contentModel.find({userId : link.userId});
    const user = await userModel.findOne({_id : link.userId});

    if(!user){
        res.status(404).json({
            msg : 'User doesnt found'
        })
        return
    }

    res.status(200).json({
        username : user.firstName,
        content
    })
})


//-------------------Main-Function---------------------------------------------------


async function main() : Promise<void> {
    try {
        await mongoose.connect(MONGO_URL);
        console.log("connected to database");
        
        app.listen(3000, () => {
            console.log('Server is running on port 3000');
        });
    }
    catch(e) {
        console.error("Failed to connect to database",e);
        
    }
}

main();



