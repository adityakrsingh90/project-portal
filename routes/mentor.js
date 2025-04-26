const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const Mentor = require('../models/mentor');
const Project = require('../models/project');
const Student = require('../models/student');
const { authenticate, authorize } = require('../middleware/auth');

/**
 * @swagger
 * tags:
 *   name: Mentor
 *   description: Operations related to mentors
 */

/**
 * @swagger
 * /mentor/login:
 *   post:
 *     summary: Mentor login.
 *     description: Logs in a mentor user.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Mentor logged in successfully. Returns JWT token and role.
 *       400:
 *         description: Invalid email or password.
 *       401:
 *         description: Invalid credentials.
 */
router.post('/login', [
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

        const token = jwt.sign({ userId: mentor._id, role: 'mentor' }, process.env.JWT_SECRET || 'your-secret-key', { expiresIn: '1h' });
        res.json({ token, role: 'mentor', userId: mentor._id });

    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /mentor/projects:
 *   get:
 *     summary: Get assigned projects for a mentor.
 *     description: Retrieves a list of projects assigned to the logged-in mentor.
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: A JSON array of projects assigned to the mentor.
 *       401:
 *         description: Unauthorized - Mentor authentication required.
 *       500:
 *         description: Server error.
 */
router.get('/projects', authenticate, authorize(['mentor']), async (req, res, next) => {
    try {
        const mentor = await Mentor.findById(req.userId).populate('assignedProjects');
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
 *     summary: Get student applications for a specific project.
 *     description: Retrieves a list of students who have applied for a specific project assigned to the logged-in mentor.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: A JSON array of students who applied for the project.
 *       401:
 *         description: Unauthorized - Mentor authentication required.
 *       404:
 *         description: Project not found.
 *       500:
 *         description: Server error.
 */
router.get('/projects/:projectId/applications', authenticate, authorize(['mentor']), async (req, res, next) => {
    const { projectId } = req.params;
    try {
        const project = await Project.findById(projectId).populate('studentsApplied', 'name rollNo email course section');
        if (!project) {
            return res.status(404).json({ errors: [{ msg: 'Project not found.' }] });
        }

        const mentor = await Mentor.findById(req.userId);
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
 *     summary: Update student progress for a project.
 *     description: Allows a mentor to update the progress of students for a specific project they are mentoring.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: string
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
 *     responses:
 *       200:
 *         description: Progress updated successfully. Returns the updated project.
 *       401:
 *         description: Unauthorized - Mentor authentication required.
 *       404:
 *         description: Project or student not found.
 *       500:
 *         description: Server error.
 */
router.put('/projects/:projectId/progress', authenticate, authorize(['mentor']), async (req, res, next) => {
    const { projectId } = req.params;
    const { studentId, progressUpdate } = req.body;

    try {
        const project = await Project.findById(projectId);
        if (!project) {
            return res.status(404).json({ errors: [{ msg: 'Project not found.' }] });
        }

        const mentor = await Mentor.findById(req.userId);
        if (!mentor || !mentor.assignedProjects.includes(projectId)) {
            return res.status(401).json({ errors: [{ msg: 'Unauthorized - You are not the mentor for this project.' }] });
        }

        const student = await Student.findById(studentId);
        if (!student || !project.studentsApplied.includes(studentId)) {
            return res.status(404).json({ errors: [{ msg: 'Student not found or not applied to this project.' }] });
        }

        const submission = {
            studentId,
            progressUpdate,
            timestamp: new Date()
        };

        project.submissions.push(submission);
        const updatedProject = await project.save();

        res.json({ message: 'Progress updated successfully.', project: updatedProject });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /mentor/profile:
 *   get:
 *     summary: Get mentor profile.
 *     description: Retrieves the profile information of the logged-in mentor.
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Mentor profile information.
 *       401:
 *         description: Unauthorized - Mentor authentication required.
 *       404:
 *         description: Mentor not found.
 *       500:
 *         description: Server error.
 */
router.get('/profile', authenticate, authorize(['mentor']), async (req, res, next) => {
    try {
        const mentor = await Mentor.findById(req.userId);
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
 *     summary: Update mentor profile.
 *     description: Allows the logged-in mentor to update their profile information.
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Profile updated successfully. Returns the updated mentor profile.
 *       400:
 *         description: Invalid email format or password length.
 *       401:
 *         description: Unauthorized - Mentor authentication required.
 *       404:
 *         description: Mentor not found.
 *       500:
 *         description: Server error.
 */
router.put('/profile', authenticate, authorize(['mentor']), [
    check('email').optional().isEmail().withMessage('Invalid email address'),
    check('password').optional().isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;
    const updateFields = {};
    if (name) updateFields.name = name;
    if (email) updateFields.email = email;
    if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        updateFields.password = hashedPassword;
    }

    try {
        const mentor = await Mentor.findByIdAndUpdate(req.userId, updateFields, { new: true, runValidators: true });
        if (!mentor) {
            return res.status(404).json({ errors: [{ msg: 'Mentor not found.' }] });
        }
        res.json({ message: 'Profile updated successfully.', mentor });
    } catch (error) {
        next(error);
    }
});

module.exports = router;
