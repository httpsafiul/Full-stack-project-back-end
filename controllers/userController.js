import UserModel from "../models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

class UserController {
  static userRegistration = async (req, res) => {
    const { name, email, password, password_confirmation, tc } = req.body;
    const user = await UserModel.findOne({ email: email });

    if (user) {
      res.send({ status: "failed", message: "Email already registered" });
    } else {
      if (name && email && password && password_confirmation && tc) {
        if (password === password_confirmation) {
          try {
            const salt = await bcrypt.genSalt(10);
            const hashPassword = await bcrypt.hash(password, salt);
            const doc = new UserModel({
              name: name,
              email: email,
              password: hashPassword,
              tc: tc,
            });
            await doc.save();
            const saved_user = await UserModel.findOne({email: email })

            // Generate JWT token 
            const token = jwt.sign({ userID: saved_user._id}, process.env.JWT_SECRET_KEY, { expiresIn: '5d'})
            res
              .status(201)
              .send({ status: "success", message: "Registration Successful", "token": token });
          } catch (error) {
            console.log(error);
            res.send({ status: "failed", message: "Cannot Register User" });
          }
        } else {
          res.send({
            status: "failed",
            message: "Password and Confirmation Password don't match",
          });
        }
      } else {
        res.send({ status: "failed", message: "All fields are required" });
      }
    }
  };

  static userLogin = async (req, res) => {
    try {
      const { email, password } = req.body;
      if (email && password) {
        const user = await UserModel.findOne({ email: email })
        if(user != null) {
            const isMatch =  await bcrypt.compare(password, user.password)
            if((user.email === email) && isMatch){
                // Generate JWT token 
            const token = jwt.sign({ userID: user._id}, process.env.JWT_SECRET_KEY, { expiresIn: '5d'})
                res.status(201).send({ status: "success", message: "Login Successful", "token": token  });
            }else{
                res.send({ status: "failed", message: "Email or Password is not Valid"});
            }
        } else{
            res.send({ status: "failed", message: "You're Not a Registered User" });
        }
      }
      else{
        res.send({ status: "failed", message: "All fields are required" });
      }
    } catch (error) {
      console.log(error);
      res.send({ status: "failed", message: "Unable to login" });
    }
  };

  static changeUserPassword =  async (req, res) => {
    const {password, password_confirmation} = req.body
    if(password && password_confirmation){
      if(password !== password_confirmation){
        res.send({ status: "failed", message: "New Password and Confirmation Password Don't Match" });
      } else{
        const salt = await bcrypt.genSalt(10);
        const newhashPassword = await bcrypt.hash(password, salt);
        await UserModel.findOneAndUpdate(req.user._id, { $set: { password: newhashPassword}})
        
        res.send({ status: "success", message: "Password changed successfully"})
      }
    } else{
      res.send({ status: "failed", message: "All fields are required" });
    }
  }

  static loggedUser = (req, res) => {
    res.send({user: req.user})
  }

  static sendPasswordResetEmail = async (req, res) => {
    const { email } = req.body
    if(email) {
      const user = await UserModel.findOne({ email: email })
      if(user){
        const secret = user._id + process.env.JWT_SECRET_KEY
        const token = jwt.sign({ userID: user._id}, secret, { expiresIn: '15m'})
        const link = `http://127.0.0.1:3000/api/user/reset/$user._id/${token}`
        console.log(link)
        res.send({status: "success", message:"Password reset email sent successfully."})
      } else{
        res.send({status: "failed", message: "Email Does not exist"})
      }
    } else{
      res.send({status: "failed", message: "Email is required"})
    }
  }

  static userPasswordReset = async(req, res) => {
    const {password, password_confirmation} = req.body
    // we get data from url by using req.params
    const {id, token} = req.params
    const user = await UserModel.findById(id)
    const new_secret = user._id + process.env.JWT_SECRET_KEY
    try {
      jwt.verify(new_secret, new_secret)
      if(password && password_confirmation){
        if(password !== password_confirmation){
          res.send({ status: "failed", message: "New Password and Confirmation Password Don't Match" });
        }else{
          const salt = await bcrypt.genSalt(10);
          const newhashPassword = await bcrypt.hash(password, salt);
          await UserModel.findOneAndUpdate(user._id, { $set: { password: newhashPassword}})
          
          res.send({ status: "success", message: "Password changed successfully"})
        }
      }
    } catch (error) {
      console.log(error)
      res.send({status:"failed", message:"Invalid token"})
    }

  }
}
export default UserController;
