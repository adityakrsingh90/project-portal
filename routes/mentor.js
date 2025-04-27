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
 *                 example: mentor@example.com
 *               password:
 *                 type: string
 *                 example: password123
 *     responses:
 *       200:
 *         description: Successfully logged in
 *       400:
 *         description: Validation error
 *       401:
 *         description: Invalid credentials
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

        const payload = { userId: mentor._id, role: 'mentor' };
        const token = jwt.sign(payload, process.env.JWT_SECRET || 'your-secret-key', { expiresIn: '1h' });

        res.json({ token, role: 'mentor', userId: mentor._id });
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
        const mentor = await Mentor.findById(req.user.userId);
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

    const { name, email, password } = req.body;
    const updateFields = {};
    if (name) updateFields.name = name;
    if (email) updateFields.email = email;
    if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        updateFields.password = hashedPassword;
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

module.exports = router;
