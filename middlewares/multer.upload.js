const path = require('path');
const multer = require('multer');
const {CloudinaryStorage} = require('multer-storage-cloudinary');
const { cloudinary } = require('../utils/cloudinary.utils');


const storage = multer.diskStorage({
    destination: function (req, file, cb) {
         
        // const mime = file.mimetype
        // console.log({mime});  
        // const _location = mime.startsWith("image/")?"images/":"videos/"
        // cb(null, "uploads/"+_location)
        cb(null, "uploads/")
    },

    filename: function (req, file, cb) {
        const ext = path.extname(file.originalname);
        const mime = file.mimetype
        // console.log({mime});  
        const _location = mime.startsWith("image/")?"images/":"videos/"
        const file_name = `${_location}${req.auth_id}_${Date.now()}${ext}`;
        
         
        cb(null, file_name)

    }
})

function  dynamicStorage(file_path){
   return   multer.diskStorage({
       destination: function (req, file, cb) {
           cb(null, "uploads/")
       },
   
       filename: function (req, file, cb) {
           const ext = path.extname(file.originalname);   
           const file_name = file_path+  Date.now() + ext;
   
           cb(null, file_name)
   
       }
   })

} 

const cloudStorage = new CloudinaryStorage({
    cloudinary: cloudinary,
})


/** Original multiple storge implementation */
const multerUploader= multer({storage: storage})

/** Direct uploader to cloudinary from multer */
const multerCloudUploader = multer({storage:cloudStorage})

/**
 * Multer Uploader with dynamic path for file saving
 * @param {string} file_path 
 * @returns multer.Multer
 */
const multerDynamicUploader= (file_path)=> multer({storage: dynamicStorage(file_path)})

module.exports = {
    multerUploader,
    multerDynamicUploader,
    multerCloudUploader,
}