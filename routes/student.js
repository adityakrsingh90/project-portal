const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const Student = require('../models/student');
const Project = require('../models/project');
const { authenticate, authorize } = require('../middleware/auth');

/**
 * @swagger
 * tags:
 *   name: Student
 *   description: Operations related to students
 */

/**
 * @swagger
 * /student/login:
 *   post:
 *     summary: Student login.
 *     description: Logs in a student user.
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
 *                 example: alice.smith@example.com
 *               password:
 *                 type: string
 *                 example: password123
 *     responses:
 *       200:
 *         description: Student logged in successfully. Returns JWT token and role.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                 role:
 *                   type: string
 *                   example: student
 *                 userId:
 *                   type: string
 *                   example: 6101b8c7d4e5f6a9b2c3d4e6
 *       400:
 *         description: Invalid email or password.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 errors:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       msg:
 *                         type: string
 *                       param:
 *                         type: string
 *                       location:
 *                         type: string
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
        const student = await Student.findOne({ email });
        if (!student) {
            const error = new Error('Invalid credentials');
            error.statusCode = 401;
            return next(error);
        }

        const isMatch = await bcrypt.compare(password, student.password);
        if (!isMatch) {
            const error = new Error('Invalid credentials');
            error.statusCode = 401;
            return next(error);
        }

        const token = jwt.sign({ userId: student._id, role: 'student' }, process.env.JWT_SECRET || 'your-secret-key', { expiresIn: '1h' });
        res.json({ token, role: 'student', userId: student._id });

    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});

/**
 * @swagger
 * /student/projects:
 *   get:
 *     summary: Get available projects for students.
 *     description: Retrieves a list of projects with 'Approved' status that students can apply for. Requires student authentication.
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: A JSON array of available projects.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   _id:
 *                     type: string
 *                   title:
 *                     type: string
 *                   description:
 *                     type: string
 *                   mentor:
 *                     type: object
 *                     properties:
 *                       _id:
 *                         type: string
 *                       name:
 *                         type: string
 *                       email:
 *                         type: string
 *       401:
 *         description: Unauthorized - Student authentication required.
 *       500:
 *         description: Server error.
 */
router.get('/projects', authenticate, authorize(['student']), async (req, res, next) => {
    try {
        const projects = await Project.find({ status: 'Approved' }).populate('mentor', 'name email');
        res.json(projects);
    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});

/**
 * @swagger
 * /student/projects/{projectId}/apply:
 *   post:
 *     summary: Apply for a project.
 *     description: Allows a logged-in student to apply for a specific project. Requires student authentication.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the project to apply for.
 *     responses:
 *       200:
 *         description: Application submitted successfully. Returns the updated project.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Application submitted successfully.
 *                 project:
 *                   type: object
 *       401:
 *         description: Unauthorized - Student authentication required.
 *       404:
 *         description: Project not found.
 *       409:
 *         description: Already applied for this project.
 *       500:
 *         description: Server error.
 */
router.post('/projects/:projectId/apply', authenticate, authorize(['student']), async (req, res, next) => {
    const { projectId } = req.params;
    const studentId = req.userId;

    try {
        const project = await Project.findById(projectId);
        if (!project) {
            const error = new Error('Project not found.');
            error.statusCode = 404;
            return next(error);
        }

        const student = await Student.findById(studentId);
        if (!student) {
            const error = new Error('Student not found.');
            error.statusCode = 404;
            return next(error);
        }

        if (project.studentsApplied.includes(studentId)) {
            const error = new Error('Already applied for this project.');
            error.statusCode = 409;
            return next(error);
        }

        project.studentsApplied.push(studentId);
        const updatedProject = await project.save();

        student.appliedProjects.push(projectId);
        await student.save();

        res.json({ message: 'Application submitted successfully.', project: updatedProject });

    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});

/**
 * @swagger
 * /student/applications:
 *   get:
 *     summary: Get applied projects for a student.
 *     description: Retrieves a list of projects the logged-in student has applied for, along with their status. Requires student authentication.
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: A JSON array of applied projects with their status.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   _id:
 *                     type: string
 *                   title:
 *                     type: string
 *                   status:
 *                     type: string
 *                     example: Pending
 *       401:
 *         description: Unauthorized - Student authentication required.
 *       500:
 *         description: Server error.
 */
router.get('/applications', authenticate, authorize(['student']), async (req, res, next) => {
    try {
        const student = await Student.findById(req.userId).populate('appliedProjects', 'title status');
        if (!student) {
            const error = new Error('Student not found.');
            error.statusCode = 404;
            return next(error);
        }
        res.json(student.appliedProjects);
    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});

/**
 * @swagger
 * /student/profile:
 *   get:
 *     summary: Get student profile.
 *     description: Retrieves the profile information of the logged-in student. Requires student authentication.
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Student profile information.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 _id:
 *                   type: string
 *                 name:
 *                   type: string
 *                 rollNo:
 *                   type: string
 *                 course:
 *                   type: string
 *                 section:
 *                   type: string
 *                 email:
 *                   type: string
 *       401:
 *         description: Unauthorized - Student authentication required.
 *       404:
 *         description: Student not found.
 *       500:
 *         description: Server error.
 */
router.get('/profile', authenticate, authorize(['student']), async (req, res, next) => {
    try {
        const student = await Student.findById(req.userId);
        if (!student) {
            const error = new Error('Student not found.');
            error.statusCode = 404;
            return next(error);
        }
        res.json(student);
    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});

/**
 * @swagger
 * /student/profile:
 *   put:
 *     summary: Update student profile.
 *     description: Allows the logged-in student to update their profile information. Requires student authentication.
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
 *                 example: Alice Smith Updated
 *               email:
 *                 type: string
 *                 format: email
 *                 example: alice.updated@example.com
 *               password:
 *                 type: string
 *                 example: newpassword123
 *     responses:
 *       200:
 *         description: Profile updated successfully. Returns the updated student profile.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Profile updated successfully.
 *                 student:
 *                   type: object
 *       401:
 *         description: Unauthorized - Student authentication required.
 *       404:
 *         description: Student not found.
 *       400:
 *         description: Invalid email format.
 *       500:
 *         description: Server error.
 */
router.put('/profile', authenticate, authorize(['student']), [
    check('email').optional().isEmail().withMessage('Invalid email address'),
    check('password').optional().isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const student = await Student.findById(req.userId);
        if (!student) {
            const error = new Error('Student not found.');
            error.statusCode = 404;
            return next(error);
        }

        if (req.body.name) student.name = req.body.name;
        if (req.body.email) student.email = req.body.email;
        if (req.body.password) student.password = await bcrypt.hash(req.body.password, 10);

        const updatedStudent = await student.save();
        res.json({ message: 'Profile updated successfully.', student: updatedStudent });
    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});

module.exports = router;
