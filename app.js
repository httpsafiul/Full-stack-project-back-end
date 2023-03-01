import dotenv from 'dotenv';
dotenv.config()
import express from 'express';
import cors from 'cors';
import connectDB from './config/connectDB.js';
import userRoutes from './routes/userRoutes.js';


const app = express();
const port = process.env.PORT
const DATABASE_URL  = process.env.DATABASE_URL

// CORS pollicy
app.use(cors());

// Database Connection
connectDB(DATABASE_URL)

// JSON
app.use(express.json())

// Load routes
app.use("/api/user", userRoutes)

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`)
})