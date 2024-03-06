const cloudinary = require('cloudinary').v2;

require('dotenv').config();

cloudinary.config({
    cloud_name: process.env.CLOUD_NAME,
    api_key: process.env.API_KEY,
    api_secret: process.env.API_SECRET
});


const cloudDelete=async(id)=>{
    try {
        await cloudinary.uploader.destroy(id);
        return {status:true, error:null} ;        
    } catch (error) {
       return {status:false, error} 
    }
}

const cloudUpload = async(file, options={})=>{
    try {
        const result = await cloudinary.uploader.upload(file, options)
        return {object: result, error:null}
    } catch (error) {
        return {object:null, error}        
    }
}

module.exports = {
    cloudinary,
    cloudUpload,
    cloudDelete
}