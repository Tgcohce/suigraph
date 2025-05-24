const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const { v4: uuidv4 } = require('uuid');

const router = express.Router();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../../uploads');
    fs.ensureDirSync(uploadDir);
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueId = uuidv4();
    const ext = path.extname(file.originalname);
    cb(null, `${uniqueId}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  // Accept .move files and text files
  if (file.originalname.endsWith('.move') || file.mimetype === 'text/plain') {
    cb(null, true);
  } else {
    cb(new Error('Only .move files are allowed'), false);
  }
};

const upload = multer({ 
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 10 // Maximum 10 files
  }
});

router.post('/', upload.array('files'), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No files uploaded' });
    }

    const fileIds = req.files.map(file => ({
      id: path.parse(file.filename).name,
      originalName: file.originalname,
      filename: file.filename,
      path: file.path,
      size: file.size
    }));

    console.log(`Uploaded ${req.files.length} files:`, fileIds.map(f => f.originalName));

    res.json({
      success: true,
      message: `Successfully uploaded ${req.files.length} file(s)`,
      fileIds: fileIds
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ 
      error: 'Upload failed', 
      message: error.message 
    });
  }
});

// Get uploaded file content
router.get('/:fileId', async (req, res) => {
  try {
    const { fileId } = req.params;
    const uploadsDir = path.join(__dirname, '../../uploads');
    
    // Find file with matching ID
    const files = await fs.readdir(uploadsDir);
    const targetFile = files.find(file => file.startsWith(fileId));
    
    if (!targetFile) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    const filePath = path.join(uploadsDir, targetFile);
    const content = await fs.readFile(filePath, 'utf8');
    
    res.json({
      id: fileId,
      filename: targetFile,
      content: content
    });
    
  } catch (error) {
    console.error('File read error:', error);
    res.status(500).json({ 
      error: 'Failed to read file', 
      message: error.message 
    });
  }
});

module.exports = router;