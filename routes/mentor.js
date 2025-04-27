const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const Mentor = require('../models/mentor');
const Project = require('../models/project');
const Student = require('../models/student');
const { authenticate, authorize } = require('../middleware/auth');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');

/**
 * @swagger
 * tags:
 *   name: Mentor
 *   description: Mentor operations
 */

/**
 * @swagger
 * /mentor/login:
 *   post:
 *     summary: Login as a mentor
 *     tags: [Mentor]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: mentor.rawat@example.com
 *               password:
 *                 type: string
 *                 example: amarjeet
 *     responses:
 *       200:
 *         description: Successfully logged in
 *       400:
 *         description: Validation error
 *       401:
 *         description: Invalid credentials
 */
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: 'Too many login attempts, please try again later.'
});

router.post('/login', loginLimiter, [
    check('email').isEmail().withMessage('Invalid email address'),
    check('password').notEmpty().withMessage('Password is required'),
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { email, password } = req.body;

    try {
        const mentor = await Mentor.findOne({ email });
        if (!mentor) {
            return res.status(401).json({ errors: [{ msg: 'Invalid credentials' }] });
        }

        const isMatch = await bcrypt.compare(password, mentor.password);
        if (!isMatch) {
            return res.status(401).json({ errors: [{ msg: 'Invalid credentials' }] });
        }

        const payload = { userId: mentor._id, role: 'mentor' };
        const token = jwt.sign(payload, process.env.JWT_SECRET || 'your-secret-key', { expiresIn: '1h' });

        res.json({ token, role: 'mentor', userId: mentor._id });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /mentor/profile:
 *   get:
 *     summary: Get mentor profile
 *     tags: [Mentor]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Mentor profile data
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Mentor not found
 */
router.get('/profile', authenticate, authorize(['mentor']), async (req, res, next) => {
    try {
        const mentor = await Mentor.findById(req.user.userId).populate('assignedProjects');
        if (!mentor) {
            return res.status(404).json({ errors: [{ msg: 'Mentor not found.' }] });
        }
        res.json(mentor);
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /mentor/profile:
 *   put:
 *     summary: Update mentor profile
 *     tags: [Mentor]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 example: New Mentor Name
 *               email:
 *                 type: string
 *                 example: newmentor@example.com
 *               password:
 *                 type: string
 *                 example: newpassword123
 *     responses:
 *       200:
 *         description: Profile updated successfully
 *       400:
 *         description: Validation errors
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Mentor not found
 */
router.put('/profile', authenticate, authorize(['mentor']), [
    check('email').optional().isEmail().withMessage('Invalid email address'),
    check('password').optional().isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const updateFields = {};
    if (req.body.name) updateFields.name = req.body.name;
    if (req.body.email) updateFields.email = req.body.email;
    if (req.body.password) {
        updateFields.password = await bcrypt.hash(req.body.password, 10);
    }

    try {
        const mentor = await Mentor.findByIdAndUpdate(req.user.userId, updateFields, { new: true, runValidators: true });
        if (!mentor) {
            return res.status(404).json({ errors: [{ msg: 'Mentor not found.' }] });
        }
        res.json({ message: 'Profile updated successfully.', mentor });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /mentor/add-student:
 *   post:
 *     summary: Add a new student
 *     tags: [Mentor]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 example: Alice Smith
 *               rollNo:
 *                 type: string
 *                 example: STU001
 *               course:
 *                 type: string
 *                 example: Computer Science
 *               section:
 *                 type: string
 *                 example: A
 *               email:
 *                 type: string
 *                 format: email
 *                 example: alice.smith@example.com
 *     responses:
 *       201:
 *         description: Student added successfully. Returns the student ID.
 *       400:
 *         description: Invalid request parameters.
 *       401:
 *         description: Unauthorized - Mentor authentication required.
 *       409:
 *         description: Student with this roll number or email already exists.
 *       500:
 *         description: Server error.
 */
router.post('/add-student', [
    check('name').notEmpty().withMessage('Name is required'),
    check('rollNo').notEmpty().isNumeric().withMessage('Roll number must be numeric'),
    check('course').notEmpty().withMessage('Course is required'),
    check('section').notEmpty().withMessage('Section is required'),
    check('email').isEmail().withMessage('Invalid email address'),
], authenticate, authorize(['mentor']), async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, rollNo, course, section, email } = req.body;

    try {
        const existingStudent = await Student.findOne({ $or: [{ rollNo }, { email }] });
        if (existingStudent) {
            return res.status(409).json({ errors: [{ msg: 'Student with this roll number or email already exists.' }] });
        }

        const generatedPassword = Math.random().toString(36).slice(-8);
        const hashedPassword = await bcrypt.hash(generatedPassword, 10);

        const newStudent = new Student({
            name,
            rollNo,
            course,
            section,
            email,
            password: hashedPassword
        });

        const savedStudent = await newStudent.save();

        // Optionally send registration email to the student
        await sendRegistrationEmail(email, generatedPassword);

        res.status(201).json({ message: 'Student added successfully.', studentId: savedStudent._id });

    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /mentor/projects:
 *   get:
 *     summary: Get projects assigned to the mentor
 *     tags: [Mentor]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of assigned projects
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Mentor not found
 */
router.get('/projects', authenticate, authorize(['mentor']), async (req, res, next) => {
    try {
        const mentor = await Mentor.findById(req.user.userId).populate('assignedProjects');
        if (!mentor) {
            return res.status(404).json({ errors: [{ msg: 'Mentor not found.' }] });
        }
        res.json(mentor.assignedProjects);
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /mentor/projects/{projectId}/applications:
 *   get:
 *     summary: Get student applications for a specific project
 *     tags: [Mentor]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: string
 *         description: Project ID
 *     responses:
 *       200:
 *         description: List of students applied
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Project not found
 */
router.get('/projects/:projectId/applications', authenticate, authorize(['mentor']), async (req, res, next) => {
    const { projectId } = req.params;
    try {
        const project = await Project.findById(projectId).populate('studentsApplied', 'name rollNo email course section');
        if (!project) {
            return res.status(404).json({ errors: [{ msg: 'Project not found.' }] });
        }

        const mentor = await Mentor.findById(req.user.userId);
        if (!mentor || !mentor.assignedProjects.includes(projectId)) {
            return res.status(401).json({ errors: [{ msg: 'Unauthorized - You are not the mentor for this project.' }] });
        }

        res.json(project.studentsApplied);
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /mentor/projects/{projectId}/progress:
 *   put:
 *     summary: Update student progress on a project
 *     tags: [Mentor]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: string
 *         description: Project ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               studentId:
 *                 type: string
 *               progressUpdate:
 *                 type: string
 *             required:
 *               - studentId
 *               - progressUpdate
 *     responses:
 *       200:
 *         description: Progress updated successfully
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Project or Student not found
 */
router.put('/projects/:projectId/progress', authenticate, authorize(['mentor']), async (req, res, next) => {
    const { projectId } = req.params;
    const { studentId, progressUpdate } = req.body;

    try {
        const project = await Project.findById(projectId);
        if (!project) {
            return res.status(404).json({ errors: [{ msg: 'Project not found.' }] });
        }

        const mentor = await Mentor.findById(req.user.userId);
        if (!mentor || !mentor.assignedProjects.includes(projectId)) {
            return res.status(401).json({ errors: [{ msg: 'Unauthorized - You are not the mentor for this project.' }] });
        }

        const student = await Student.findById(studentId);
        if (!student || !project.studentsApplied.includes(studentId)) {
            return res.status(404).json({ errors: [{ msg: 'Student not found or not applied to this project.' }] });
        }

        project.submissions.push({
            studentId,
            progressUpdate,
            timestamp: new Date()
        });

        const updatedProject = await project.save();
        res.json({ message: 'Progress updated successfully.', project: updatedProject });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /mentor/projects/{projectId}/approve:
 *   put:
 *     summary: Approve a project
 *     tags: [Mentor]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: string
 *         description: Project ID
 *     responses:
 *       200:
 *         description: Project approved successfully
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Project not found
 */
router.put('/projects/:projectId/approve', authenticate, authorize(['mentor']), async (req, res, next) => {
    const { projectId } = req.params;

    try {
        const project = await Project.findById(projectId);
        if (!project) {
            return res.status(404).json({ errors: [{ msg: 'Project not found.' }] });
        }

        project.status = 'Approved';
        await project.save();

        // Notify students...

        res.json({ message: 'Project approved successfully.', project });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /mentor/projects/{projectId}/reject:
 *   put:
 *     summary: Reject a project
 *     tags: [Mentor]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: string
 *         description: Project ID
 *     responses:
 *       200:
 *         description: Project rejected successfully
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Project not found
 */
router.put('/projects/:projectId/reject', authenticate, authorize(['mentor']), async (req, res, next) => {
    const { projectId } = req.params;

    try {
        const project = await Project.findById(projectId);
        if (!project) {
            return res.status(404).json({ errors: [{ msg: 'Project not found.' }] });
        }

        project.status = 'Rejected';
        await project.save();

        // Notify students...

        res.json({ message: 'Project rejected successfully.', project });
    } catch (error) {
        next(error);
    }
});

// Function to send student registration email
async function sendRegistrationEmail(toEmail, password) {
    const transporter = nodemailer.createTransport({
        service: 'gmail', // e.g., 'gmail', 'Outlook'
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: toEmail,
        subject: 'Welcome to the Real Time Project Portal!',
        html: `<p>Dear Student,</p><p>You have been successfully registered on the Real Time Project Portal.</p><p>Your auto-generated password is: <strong>${password}</strong></p><p>Please log in and you can change your password in your profile section.</p><p>Best regards,<br>The Project Portal Team</p>`
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Registration email sent to ${toEmail}`);
    } catch (error) {
        console.error('Error sending registration email:', error);
    }
}

/**
 * @swagger
 * /mentor/stats:
 *   get:
 *     summary: Get total number of students and projects
 *     tags: [Mentor]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Total counts of students and projects
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 totalStudents:
 *                   type: number
 *                   example: 100
 *                 totalProjects:
 *                   type: number
 *                   example: 20
 *       401:
 *         description: Unauthorized
 */
router.get('/stats', authenticate, authorize(['mentor']), async (req, res, next) => {
    try {
        const totalStudents = await Student.countDocuments();
        const totalProjects = await Project.countDocuments();

        res.json({
            totalStudents,
            totalProjects
        });
    } catch (error) {
        next(error);
    }
});


/**
 * @swagger
 * /mentor/students/projects:
 *   get:
 *     summary: Get all student details with their projects
 *     tags: [Mentor]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of all students with their projects
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   _id:
 *                     type: string
 *                   name:
 *                     type: string
 *                   rollNo:
 *                     type: string
 *                   course:
 *                     type: string
 *                   section:
 *                     type: string
 *                   email:
 *                     type: string
 *                   appliedProjects:
 *                     type: array
 *                     items:
 *                       type: object
 *                       properties:
 *                         _id:
 *                           type: string
 *                         title:
 *                           type: string
 *                         status:
 *                           type: string
 *       401:
 *         description: Unauthorized
 */
router.get('/students/projects', authenticate, authorize(['mentor']), async (req, res, next) => {
    try {
        const students = await Student.find().populate('appliedProjects', 'title status'); // Fetch all students and populate their applied projects
        res.json(students); // Return the list of students with their projects
    } catch (error) {
        next(error); // Handle any errors
    }
});

module.exports = router;