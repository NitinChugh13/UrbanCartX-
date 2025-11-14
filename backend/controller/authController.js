import User from "../model/userModel.js"
import validator from "validator"
import bcrypt from "bcryptjs"
import { genrateToken } from "../config/token.js"


export const registration = async(req,res)=>{
    try{
        const {name , email , password} = req.body
        const existUser = await User.findOne({email})
        if(existUser){
            return res.status(400).json({message : "User already Exist"})
        }
        if(!validator.isEmail(email)){
            return res.status(400).json({message : "Enter Valid Email"})
        }
        if(password.length < 8){
            return res.status(400).json({message : "Enter Strong Password"})
        }
        let hashPassword = await bcrypt.hash(password , 10)

        const user = await User.create({name,email,password:hashPassword})
        let token = genrateToken(user._id)
        res.cookie("token",token,{
            httpOnly:true,
            secure: false,
            sameSite:"Strict",
            maxAge: 7 * 24 * 60 * 60 * 1000

        })
        return res.status(201).json(user)
    }catch(error){
        console.log("SignUp error")
        return res.status(500).json({message:`Registeration error ${error}`})
    }
}

export const login = async(req,res)=>{
    try {
        let {email,password} =req.body;
        let user = await User.findOne({email})
        if(!user){
            return res.status(404).json({message: "User not found "})
        }
        let isMatch = await bcrypt.compare(password , user.password)
        if(!isMatch){
             return res.status(400).json({message: "Incorrect Password "})
        }
        let token = genrateToken(user._id)
        res.cookie("token",token,{
            httpOnly:true,
            secure: false,
            sameSite:"Strict",
            maxAge: 7 * 24 * 60 * 60 * 1000

        })
        return res.status(201).json(user)
    } catch(error){
        console.log("Login error")
        return res.status(500).json({message:`Login error ${error}`})
    }
}

export const logout = async (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: true,
      sameSite: "none"
    });

    return res.status(200).json({ message: "Logout Successful" });
  } catch (error) {
    console.log("Logout error:", error);
    return res.status(500).json({ message: `Logout error: ${error.message}` });
  }
};
