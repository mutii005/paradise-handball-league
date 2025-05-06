// api/register.js
// This is a Node.js Serverless Function for Vercel

// Import necessary libraries
// You will need to install 'formidable' and potentially libraries for cloud storage (e.g., AWS SDK)
// using npm or yarn in your project root:
// npm install formidable @aws-sdk/client-s3 @aws-sdk/lib-storage
// or
// yarn add formidable @aws-sdk/client-s3 @aws-sdk/lib-storage

const formidable = require('formidable');
// const { S3Client } = require("@aws-sdk/client-s3"); // Uncomment if using AWS S3
// const { Upload } = require("@aws-sdk/lib-storage"); // Uncomment if using AWS S3
const fs = require('fs'); // Node.js file system module (for reading temporary files)


// --- Configuration ---
// These should ideally be stored as Environment Variables in Vercel for security
// For AWS S3 example:
// const AWS_S3_REGION = process.env.AWS_S3_REGION;
// const AWS_S3_BUCKET_NAME = process.env.AWS_S3_BUCKET_NAME;
// const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID; // Use IAM roles if possible instead of keys
// const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY; // Use IAM roles if possible instead of keys

// Initialize S3 Client (for AWS S3 example)
// const s3Client = new S3Client({
//     region: AWS_S3_REGION,
//     credentials: {
//         accessKeyId: AWS_ACCESS_KEY_ID,
//         secretAccessKey: AWS_SECRET_ACCESS_KEY,
//     },
// });


// Registration End Date (YYYY-MM-DDTHH:MM:SS format)
const REGISTRATION_END_DATE_STR = "2025-05-10T23:59:59";

// Allowed file types and max size (should match frontend validation)
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/jpg'];
const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2 MB


// --- Helper Function to Sanitize Input ---
function sanitizeInput(data) {
    if (typeof data !== 'string') {
        return data; // Return non-string data as is
    }
    // Basic sanitization: remove leading/trailing whitespace and escape HTML entities
    return data.trim().replace(/[&<>"']/g, (match) => {
        const escape = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        };
        return escape[match];
    });
}

// --- Helper Function to Sanitize Directory Name ---
function sanitizeDirname(name) {
    if (typeof name !== 'string') {
        return 'unknown_player';
    }
    // Remove characters not suitable for directory names
    let safeName = name.replace(/[^\p{L}\p{N}\s-]/gu, ''); // Allow letters, numbers, spaces, hyphens (Unicode aware)
    safeName = safeName.replace(/\s+/g, '_'); // Replace spaces with underscores
    safeName = safeName.toLowerCase(); // Convert to lowercase
    safeName = safeName.substring(0, 50); // Limit length
    safeName = safeName.replace(/_+$/, ''); // Trim trailing underscores
    return safeName || 'player_' + Date.now(); // Fallback if empty
}

// --- Helper Function to Validate Data ---
function validateData(fields, files) {
    const errors = [];

    // Basic required field checks
    const requiredFields = [
        'email', 'name', 'father_name', 'mother_name', 'dob', 'phone', 'gender',
        'district', 'aadhaar', 'district_achievements', 'state_achievements',
        'national_achievements', 'player_position', 'basic_price'
    ];

    requiredFields.forEach(field => {
        if (!fields[field] || fields[field].trim() === '') {
            errors.push(`Missing required field: ${field.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}`);
        }
    });

    // File upload checks
    const requiredFiles = ['passport_photo', 'payment_screenshot'];
     requiredFiles.forEach(fileKey => {
        if (!files[fileKey] || files[fileKey].length === 0) {
            errors.push(`Missing required file upload: ${fileKey.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}`);
        } else {
            const file = files[fileKey][0]; // formidable returns an array for single file input

            if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
                 errors.push(`Invalid file type for ${fileKey.replace(/_/g, ' ')}. Only JPG, PNG allowed.`);
            }
            if (file.size > MAX_FILE_SIZE) {
                 errors.push(`File size for ${fileKey.replace(/_/g, ' ')} exceeds ${MAX_FILE_SIZE / 1024 / 1024}MB limit.`);
            }
        }
    });


    // Specific format validations (basic examples)
    if (fields.email && !/^\S+@\S+\.\S+$/.test(fields.email)) {
        errors.push('Invalid email format.');
    }
    if (fields.phone && !/^[6-9]\d{9}$/.test(fields.phone)) {
        errors.push('Invalid phone number format (must be 10 digits starting with 6-9).');
    }
    if (fields.aadhaar && !/^\d{12}$/.test(fields.aadhaar)) {
        errors.push('Invalid Aadhaar number format (must be 12 digits).');
    }
    if (fields.basic_price) {
        const price = parseInt(fields.basic_price, 10);
        if (isNaN(price) || price < 50 || price > 200 || (price % 10 !== 0)) {
            errors.push('Invalid Basic Price. Must be a whole number between 50 and 200, in steps of 10.');
        }
    }
     if (fields.dob) {
        try {
            const dobDate = new Date(fields.dob);
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            if (isNaN(dobDate.getTime()) || dobDate >= today) {
                errors.push('Date of Birth must be a valid date in the past.');
            }
        } catch (e) {
             errors.push('Invalid Date of Birth format provided.');
        }
    }


    return errors;
}

// --- Check Registration Deadline ---
function isRegistrationOpen() {
    try {
        const now = new Date();
        const endDate = new Date(REGISTRATION_END_DATE_STR);
        return now <= endDate;
    } catch (e) {
        console.error("Error parsing registration end date:", e);
        return false; // Assume closed if date parsing fails
    }
}


// --- Main Serverless Function Handler ---
module.exports = async (req, res) => {
    // Only allow POST requests
    if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        return res.status(405).json({ message: 'Method Not Allowed' });
    }

    // Check registration deadline
     if (!isRegistrationOpen()) {
         return res.status(400).json({ message: 'Registration is closed.' });
     }


    // Parse the incoming form data (including files)
    const form = formidable({
        multiples: false, // Assuming only one file per input name
        uploadDir: '/tmp', // Use Vercel's temporary directory for uploads
        keepExtensions: true, // Keep file extensions
        maxFileSize: MAX_FILE_SIZE, // Enforce max file size
    });

    let fields;
    let files;

    try {
        [fields, files] = await new Promise((resolve, reject) => {
            form.parse(req, (err, fields, files) => {
                if (err) {
                    console.error('Formidable parse error:', err);
                    // Handle specific formidable errors like file size limit
                    if (err.code === formidable.errors.biggerThanMaxFileSize) {
                         return reject({ status: 413, message: `File size exceeds limit (${MAX_FILE_SIZE / 1024 / 1024}MB).` });
                    }
                    return reject({ status: 500, message: 'Error processing form data.' });
                }
                // formidable returns fields and files as arrays of strings/objects
                // Convert them to single values if only one is expected per field name
                 const singleFields = {};
                 for (const key in fields) {
                     singleFields[key] = Array.isArray(fields[key]) ? fields[key][0] : fields[key];
                 }
                 const singleFiles = {};
                 for (const key in files) {
                     singleFiles[key] = Array.isArray(files[key]) ? files[key] : [files[key]]; // Keep files as array for easier handling
                 }
                resolve([singleFields, singleFiles]);
            });
        });
    } catch (error) {
        console.error('Error parsing form data:', error);
         // Use the status from the caught error if available, otherwise default to 500
        const statusCode = error.status || 500;
        const message = error.message || 'Error processing form data.';
        return res.status(statusCode).json({ message: message });
    }

    // Sanitize input fields
    const sanitizedFields = {};
    for (const key in fields) {
        sanitizedFields[key] = sanitizeInput(fields[key]);
    }

    // Validate the sanitized data and files
    const validationErrors = validateData(sanitizedFields, files);

    if (validationErrors.length > 0) {
        console.error('Validation Errors:', validationErrors);
        // Clean up temporary files if validation fails after parsing
        for (const fileKey in files) {
            files[fileKey].forEach(file => {
                try { fs.unlinkSync(file.filepath); } catch (e) { console.error("Error cleaning up temp file:", e); }
            });
        }
        return res.status(400).json({ message: 'Validation failed', errors: validationErrors });
    }

    // --- Data Processing and Storage (Requires External Services) ---

    // Prepare player folder name
    const playerName = sanitizedFields.name || 'unknown_player';
    const playerFolderName = sanitizeDirname(playerName);

    // Access uploaded files (these are temporary files in /tmp)
    const passportPhotoTemp = files.passport_photo ? files.passport_photo[0] : null;
    const paymentScreenshotTemp = files.payment_screenshot ? files.payment_screenshot[0] : null;

    // *** IMPORTANT: Persistent Storage Required ***
    // Vercel Serverless Functions are stateless. You CANNOT save files directly
    // to the function's file system (/tmp) for long-term storage.
    // You MUST use a separate persistent storage solution like:
    // - AWS S3
    // - Google Cloud Storage
    // - Vercel Blob / Vercel Artifacts (Check Vercel documentation for suitability for user uploads)
    // - Other cloud storage providers

    const uploadedFilePaths = {}; // To store paths/URLs after uploading to cloud storage

    try {
        // Example conceptual code for uploading to AWS S3 (requires AWS SDK setup and configuration)
        // if (passportPhotoTemp) {
        //     const photoKey = `${playerFolderName}/${passportPhotoTemp.newFilename}`; // Key in S3 bucket
        //     const photoUpload = new Upload({
        //         client: s3Client,
        //         params: {
        //             Bucket: AWS_S3_BUCKET_NAME,
        //             Key: photoKey,
        //             Body: fs.createReadStream(passportPhotoTemp.filepath), // Read from the temporary file
        //             ContentType: passportPhotoTemp.mimetype, // Set correct content type
        //         },
        //     });
        //     await photoUpload.done();
        //     uploadedFilePaths.passport_photo = `s3://${AWS_S3_BUCKET_NAME}/${photoKey}`; // Store S3 path or a public URL
        // }

        // if (paymentScreenshotTemp) {
        //     const screenshotKey = `${playerFolderName}/${paymentScreenshotTemp.newFilename}`; // Key in S3 bucket
        //     const screenshotUpload = new Upload({
        //         client: s3Client,
        //         params: {
        //             Bucket: AWS_S3_BUCKET_NAME,
        //             Key: screenshotKey,
        //             Body: fs.createReadStream(paymentScreenshotTemp.filepath), // Read from the temporary file
        //             ContentType: paymentScreenshotTemp.mimetype, // Set correct content type
        //         },
        //     });
        //     await screenshotUpload.done();
        //     uploadedFilePaths.payment_screenshot = `s3://${AWS_S3_BUCKET_NAME}/${screenshotKey}`; // Store S3 path or a public URL
        // }

        // *** IMPORTANT: Data Storage Required ***
        // You also cannot reliably append to a CSV file on the function's file system.
        // You need a persistent storage solution for the text data:
        // - Append data to a file in cloud storage (e.g., S3)
        // - Save data to a database (e.g., PostgreSQL, MongoDB, Vercel Postgres)
        // - Use a dedicated form submission service

        const registrationData = {
            timestamp: new Date().toISOString(),
            ...sanitizedFields,
            // Include paths/URLs to saved files in cloud storage
            passport_photo_storage_path: uploadedFilePaths.passport_photo || null,
            payment_screenshot_storage_path: uploadedFilePaths.payment_screenshot || null,
        };

        // Example conceptual code to save registrationData (e.g., append to a file in S3 or save to a database)
        // if (AWS_S3_BUCKET_NAME) { // Example: Append to a CSV file in S3
        //     const csvFileName = '_private_data/registrations.csv'; // Key for your CSV file in S3
        //     // You would need logic here to fetch the current CSV, append the new row, and upload it back.
        //     // This is complex for concurrent writes and a database is usually better.
        //     console.log('Would append data to CSV in S3:', registrationData);
        // } else { // Example: Save to a database
        //     // Code here to insert registrationData into your database
        //     console.log('Would save data to database:', registrationData);
        // }


        // --- Respond to the Client ---
        // Assuming data saving and email sending logic would go above this line
        // If data saving failed, you would return an error response here.
        // For now, we'll return a success response assuming the conceptual saving worked.

        // Clean up temporary files after successful processing
        for (const fileKey in files) {
            files[fileKey].forEach(file => {
                try { fs.unlinkSync(file.filepath); } catch (e) { console.error("Error cleaning up temp file:", e); }
            });
        }

        // Return a success response
        res.status(200).json({ message: 'Registration submitted successfully. Admin will verify details.' });

    } catch (error) {
        console.error('Error during file upload or data saving:', error);
        // Clean up temporary files if an error occurred after parsing
        for (const fileKey in files) {
            files[fileKey].forEach(file => {
                try { fs.unlinkSync(file.filepath); } catch (e) { console.error("Error cleaning up temp file after error:", e); }
            });
        }
        // Return an error response
        return res.status(500).json({ message: 'An error occurred while saving your data.', error: error.message });
    }
};

// Disable Vercel's default bodyParser to allow formidable to handle the raw request body
export const config = {
  api: {
    bodyParser: false,
  },
};
