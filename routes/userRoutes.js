import express from "express";
const router = express.Router();
import UserController from "../controllers/userController.js";
import checkUserAuth from "../middlewares/auth-middleware.js";


// Route level middleware -  to protect route
router.use('/changepassword', checkUserAuth)
router.use('/loggedUser', checkUserAuth)



// Public routes
router.post('/register', UserController.userRegistration)
router.post('/login', UserController.userLogin)
router.post('/sendResetPasswordEmail', UserController.sendPasswordResetEmail)
router.post('/resetPassword/:id/:token', UserController.userPasswordReset)



// Protected routes
router.post('/changepassword', UserController.changeUserPassword)
router.get('/loggedUser', UserController.loggedUser)

export default router