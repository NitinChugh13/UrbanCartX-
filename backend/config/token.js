import jwt from "jsonwebtoken"
export const genrateToken = async(userID)=>{
    try {
        let token = await jwt.sign({userId} , process.env.JWT_SECRET , {expiresIn : "7d"})
        return token
    } catch (error) {
        console.log("token error")
    }
}