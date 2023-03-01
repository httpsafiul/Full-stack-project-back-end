import mongoose from "mongoose";

const connectDB = async (DATABASE_URL) => {
    try{
        const DB_OPTION = {
            dbName: "shop"
        }
        await mongoose.connect(DATABASE_URL, DB_OPTION)
        console.log('Connectde Successfully...')
    } catch(error) {
        console.log(error)
    }
}

export default connectDB