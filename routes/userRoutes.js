import express from "express";
const router = express.Router();
import UserController from "../controllers/userController.js";

// Public routes
router.post('/register', UserController.userRegistration)
router.post('/login', UserController.userLogin)

// Private routes

export default router