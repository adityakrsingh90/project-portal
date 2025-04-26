const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const Student = require('../models/student');
const Mentor = require('../models/mentor');
const Project = require('../models/project');
const nodemailer = require('nodemailer');
const { authenticate, authorize } = require('../middleware/auth');
const mongoose = require('mongoose'); // Import mongoose

// /**
//  * @swagger
//  * tags:
//  * name: Admin
//  * description: Admin-related operations
//  */

// Fixed admin credentials (in a real production app, these should be more secure)
const ADMIN_EMAIL = 'admin@example.com';
const ADMIN_PASSWORD = 'adminpassword';

/**
 * @swagger
 * /admin/login:
 *   post:
 *     summary: Admin login
 *     description: Logs in an admin user and returns JWT token.
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
 *                 example: admin@example.com
 *               password:
 *                 type: string
 *                 example: adminpassword
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                 role:
 *                   type: string
 *                   example: admin
 *       400:
 *         description: Invalid input
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

    if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
        const token = jwt.sign({ userId: 'admin', role: 'admin' }, process.env.JWT_SECRET || 'your-secret-key', { expiresIn: '1h' });
        res.json({ token, role: 'admin' });
    } else {
        const error = new Error('Invalid credentials');
        error.statusCode = 401;
        return next(error);
    }
});

async function sendEmail(to, subject, html) {
    const transporter = nodemailer.createTransport({
        service: 'gmail', // e.g., 'gmail', 'Outlook'
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: to,
        subject: subject,
        html: html
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Email sent to ${to}: ${subject}`);
    } catch (error) {
        console.error('Error sending email:', error);
    }
}

/**
 * @swagger
 * /admin/projects:
 *   get:
 *     summary: Get all projects.
 *     description: Retrieves a list of all projects with mentor details. Requires admin authentication.
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: A JSON array of all projects.
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
 *         description: Unauthorized - Admin authentication required.
 */
router.get('/projects', authenticate, authorize(['admin']), async (req, res, next) => {
    try {
        const projects = await Project.find().populate('mentor', 'name email');
        res.json(projects);
    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});

/**
 * @swagger
 * /admin/projects/pending:
 *   get:
 *     summary: Get all pending projects.
 *     description: Retrieves a list of all projects with 'Pending' status, including mentor and applied students. Requires admin authentication.
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: A JSON array of pending projects.
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
 *                   mentor:
 *                     type: object
 *                     properties:
 *                       _id:
 *                         type: string
 *                       name:
 *                         type: string
 *                       email:
 *                         type: string
 *                   studentsApplied:
 *                     type: array
 *                     items:
 *                       type: object
 *                       properties:
 *                         _id:
 *                           type: string
 *                         name:
 *                           type: string
 *                         rollNo:
 *                           type: string
 *                         email:
 *                           type: string
 *       401:
 *         description: Unauthorized - Admin authentication required.
 */
router.get('/projects/pending', authenticate, authorize(['admin']), async (req, res, next) => {
    try {
        const pendingProjects = await Project.find({ status: 'Pending' }).populate('mentor', 'name email').populate('studentsApplied', 'name rollNo email');
        res.json(pendingProjects);
    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});

/**
 * @swagger
 * /admin/projects/filter:
 *   get:
 *     summary: Filter projects (currently not implemented for course/section).
 *     description: Attempts to filter projects by course and/or section (currently returns an error). Requires admin authentication.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: course
 *         schema:
 *           type: string
 *         description: Course to filter by (not yet implemented).
 *       - in: query
 *         name: section
 *         schema:
 *           type: string
 *         description: Section to filter by (not yet implemented).
 *     responses:
 *       400:
 *         description: Filtering by course or section is not yet implemented.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Course based filtering is not yet implemented as per the current project structure.
 *       200:
 *         description: A JSON array of projects (without filtering if no valid query).
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
 *         description: Unauthorized - Admin authentication required.
 */

router.get('/projects/filter', authenticate, authorize(['admin']), async (req, res, next) => {
    const { course, section } = req.query;
    const filter = {};

    if (course) {
        return res.status(400).json({ message: 'Course based filtering is not yet implemented as per the current project structure.' });
    }

    if (section) {
        return res.status(400).json({ message: 'Section based filtering is not yet implemented as per the current project structure.' });
    }

    try {
        const projects = await Project.find(filter).populate('mentor', 'name email');
        res.json(projects);
    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});


/**
 * @swagger
 * /admin/projects/{projectId}/assign-mentor:
 *   put:
 *     summary: Assign a mentor to a project.
 *     description: Assigns a specific mentor to a project. Requires admin authentication.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the project to assign the mentor to.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               mentorId:
 *                 type: string
 *                 description: ID of the mentor to assign.
 *     responses:
 *       200:
 *         description: Mentor assigned to project successfully. Returns the updated project.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Mentor assigned to project successfully.
 *                 project:
 *                   type: object
 *                   properties:
 *                     _id:
 *                       type: string
 *                     title:
 *                       type: string
 *                     mentor:
 *                       type: object
 *                       properties:
 *                         _id:
 *                           type: string
 *                         name:
 *                           type: string
 *                         email:
 *                           type: string
 *       400:
 *         description: Invalid request parameters.
 *       401:
 *         description: Unauthorized - Admin authentication required.
 *       404:
 *         description: Project or mentor not found.
 *       500:
 *         description: Server error.
 */

router.put('/projects/:projectId/assign-mentor', authenticate, authorize(['admin']), async (req, res, next) => {
    const { projectId } = req.params;
    const { mentorId } = req.body;

    try {
        const project = await Project.findById(projectId).populate('mentor', 'name email');
        if (!project) {
            const error = new Error('Project not found.');
            error.statusCode = 404;
            return next(error);
        }

        const mentor = await Mentor.findById(mentorId);
        if (!mentor) {
            const error = new Error('Mentor not found.');
            error.statusCode = 404;
            return next(error);
        }

        const previousMentor = project.mentor;
        project.mentor = mentorId;
        const updatedProject = await project.save();

        mentor.assignedProjects.push(projectId);
        await mentor.save();

        // Send email notification to the newly assigned mentor
        const subject = `You have been assigned to project "${project.title}"`;
        const html = `<p>Dear ${mentor.name},</p><p>You have been assigned as the mentor for the project "${project.title}".</p><p>Please log in to the portal for further details and to view student applications.</p><p>Best regards,<br>The Project Portal Team</p>`;
        sendEmail(mentor.email, subject, html);

        // Optionally, send email to the previous mentor if there was one
        if (previousMentor && previousMentor._id.toString() !== mentorId) {
            const prevMentorData = await Mentor.findById(previousMentor._id);
            if (prevMentorData) {
                prevMentorData.assignedProjects = prevMentorData.assignedProjects.filter(id => id.toString() !== projectId);
                await prevMentorData.save();
                const prevSubject = `You have been unassigned from project "${project.title}"`;
                const prevHtml = `<p>Dear ${prevMentorData.name},</p><p>You have been unassigned as the mentor for the project "${project.title}".</p><p>Best regards,<br>The Project Portal Team</p>`;
                sendEmail(prevMentorData.email, prevSubject, prevHtml);
            }
        }

        res.json({ message: 'Mentor assigned to project successfully.', project: updatedProject });

    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});

/**
 * @swagger
 * /admin/projects/{projectId}/approve:
 *   put:
 *     summary: Approve a project.
 *     description: Approves a project, changing its status to 'Approved' and notifying applied students. Requires admin authentication.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the project to approve.
 *     responses:
 *       200:
 *         description: Project approved successfully. Returns the updated project.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Project approved successfully.
 *                 project:
 *                   type: object
 *                   properties:
 *                     _id:
 *                       type: string
 *                     title:
 *                       type: string
 *                     status:
 *                       type: string
 *       400:
 *         description: Project is not pending for approval.
 *       401:
 *         description: Unauthorized - Admin authentication required.
 *       404:
 *         description: Project not found.
 *       500:
 *         description: Server error.
 */
router.put('/projects/:projectId/approve', authenticate, authorize(['admin']), async (req, res, next) => {
    const { projectId } = req.params;

    try {
        const project = await Project.findById(projectId).populate('studentsApplied', 'name email');
        if (!project) {
            const error = new Error('Project not found.');
            error.statusCode = 404;
            return next(error);
        }

        if (project.status !== 'Pending') {
            const error = new Error('Project is not pending for approval.');
            error.statusCode = 400;
            return next(error);
        }

        project.status = 'Approved';
        const updatedProject = await project.save();

        // Send email notification to students who applied
        project.studentsApplied.forEach(student => {
            const subject = `Project "${project.title}" Approved!`;
            const html = `<p>Dear ${student.name},</p><p>Your application for the project "${project.title}" has been approved.</p><p>Please log in to the portal for further details.</p><p>Best regards,<br>The Project Portal Team</p>`;
            sendEmail(student.email, subject, html);
        });

        res.json({ message: 'Project approved successfully.', project: updatedProject });

    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});


/**
 * @swagger
 * /admin/projects/{projectId}/reject:
 *   put:
 *     summary: Reject a project.
 *     description: Rejects a project, changing its status to 'Rejected' and notifying applied students. Requires admin authentication.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the project to reject.
 *     responses:
 *       200:
 *         description: Project rejected successfully. Returns the updated project.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Project rejected successfully.
 *                 project:
 *                   type: object
 *                   properties:
 *                     _id:
 *                       type: string
 *                     title:
 *                       type: string
 *                     status:
 *                       type: string
 *       400:
 *         description: Project is not pending for rejection.
 *       401:
 *         description: Unauthorized - Admin authentication required.
 *       404:
 *         description: Project not found.
 *       500:
 *         description: Server error.
 */
router.put('/projects/:projectId/reject', authenticate, authorize(['admin']), async (req, res, next) => {
    const { projectId } = req.params;

    try {
        const project = await Project.findById(projectId).populate('studentsApplied', 'name email');
        if (!project) {
            const error = new Error('Project not found.');
            error.statusCode = 404;
            return next(error);
        }

        if (project.status !== 'Pending') {
            const error = new Error('Project is not pending for rejection.');
            error.statusCode = 400;
            return next(error);
        }

        project.status = 'Rejected';
        const updatedProject = await project.save();

        // Send email notification to students who applied
        project.studentsApplied.forEach(student => {
            const subject = `Project "${project.title}" Rejected`;
            const html = `<p>Dear ${student.name},</p><p>Your application for the project "${project.title}" has been rejected.</p><p>Please check other available projects on the project portal Team</p>`;
            sendEmail(student.email, subject, html);
        });

        res.json({ message: 'Project rejected successfully.', project: updatedProject });

    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});

/**
 * @swagger
 * /admin/projects/{projectId}/progress:
 *   get:
 *     summary: Get progress of students for a specific project (Admin).
 *     description: Retrieves the progress of students for a given project. Requires admin authentication.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the project to view progress for.
 *     responses:
 *       200:
 *         description: Progress details for the project.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 title:
 *                   type: string
 *                   example: Sample Project
 *                 progress:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       studentId:
 *                         type: object
 *                         properties:
 *                           _id:
 *                             type: string
 *                           name:
 *                             type: string
 *                           rollNo:
 *                             type: string
 *                           email:
 *                             type: string
 *                       progressUpdates:
 *                         type: array
 *                         items:
 *                           type: object
 *                           properties:
 *                             // Define properties for progress updates here
 *       401:
 *         description: Unauthorized - Admin authentication required.
 *       404:
 *         description: Project not found.
 *       500:
 *         description: Server error.
 */
router.get('/projects/:projectId/progress', authenticate, authorize(['admin']), async (req, res, next) => {
    const { projectId } = req.params;

    try {
        const project = await Project.findById(projectId).populate('submissions.studentId', 'name rollNo email');
        if (!project) {
            const error = new Error('Project not found.');
            error.statusCode = 404;
            return next(error);
        }

        res.json({ title: project.title, progress: project.submissions });

    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});

/**
 * @swagger
 * /admin/add-student:
 *   post:
 *     summary: Add a new student (Admin).
 *     description: Adds a new student to the system. Requires admin authentication.
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
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Student added successfully.
 *                 studentId:
 *                   type: string
 *                   example: 60f8a7b2e9d3f4125c8b7a9d
 *       400:
 *         description: Invalid request parameters.
 *       401:
 *         description: Unauthorized - Admin authentication required.
 *       409:
 *         description: Student with this roll number or email already exists.
 *       500:
 *         description: Server error.
 */
router.post('/add-student', [
    check('name').notEmpty().withMessage('Name is required'),
    check('rollNo').notEmpty().withMessage('Roll number is required'),
    check('rollNo').isNumeric().withMessage('Roll number must be numeric'),
    check('course').notEmpty().withMessage('Course is required'),
    check('section').notEmpty().withMessage('Section is required'),
    check('email').isEmail().withMessage('Invalid email address'),
], authenticate, authorize(['admin']), async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, rollNo, course, section, email } = req.body;

    try {
        const existingStudent = await Student.findOne({ $or: [{ rollNo }, { email }] });
        if (existingStudent) {
            const error = new Error('Student with this roll number or email already exists.');
            error.statusCode = 409;
            return next(error);
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

        await sendRegistrationEmail(email, generatedPassword);

        res.status(201).json({ message: 'Student added successfully.', studentId: savedStudent._id });

    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});

/**
 * @swagger
 * /admin/update-student/{studentId}:
 *   put:
 *     summary: Update an existing student (Admin).
 *     description: Updates the details of an existing student. Requires admin authentication.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: studentId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the student to update.
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
 *               course:
 *                 type: string
 *                 example: Information Technology
 *               section:
 *                 type: string
 *                 example: B
 *               email:
 *                 type: string
 *                 format: email
 *                 example: alice.updated@example.com
 *     responses:
 *       200:
 *         description: Student updated successfully. Returns the updated student details.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Student updated successfully.
 *                 student:
 *                   type: object
 *                   properties:
 *                     _id:
 *                       type: string
 *                     name:
 *                       type: string
 *                     course:
 *                       type: string
 *                     section:
 *                       type: string
 *                     email:
 *                       type: string
 *       400:
 *         description: Invalid request parameters.
 *       401:
 *         description: Unauthorized - Admin authentication required.
 *       404:
 *         description: Student not found.
 *       500:
 *         description: Server error.
 */
router.put('/update-student/:studentId', authenticate, authorize(['admin']), async (req, res, next) => {
    const { studentId } = req.params;
    const { name, course, section, email } = req.body;

    try {
        const student = await Student.findByIdAndUpdate(
            studentId,
            { name, course, section, email },
            { new: true, runValidators: true }
        );
        if (!student) {
            const error = new Error('Student not found.');
            error.statusCode = 404;
            return next(error);
        }
        res.json({ message: 'Student updated successfully.', student });
    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});

/**
 * @swagger
 * /admin/delete-student/{studentId}:
 *   delete:
 *     summary: Delete a student (Admin).
 *     description: Deletes an existing student from the system. Requires admin authentication.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: studentId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the student to delete.
 *     responses:
 *       200:
 *         description: Student deleted successfully. Returns a success message.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Student deleted successfully.
 *       401:
 *         description: Unauthorized - Admin authentication required.
 *       404:
 *         description: Student not found.
 *       500:
 *         description: Server error.
 */
router.delete('/delete-student/:studentId', authenticate, authorize(['admin']), async (req, res, next) => {
    const { studentId } = req.params;
    try {
        const student = await Student.findByIdAndDelete(studentId);
        if (!student) {
            const error = new Error('Student not found.');
            error.statusCode = 404;
            return next(error);
        }
        res.json({ message: 'Student deleted successfully.' });
    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});

/**
 * @swagger
 * /admin/add-mentor:
 *   post:
 *     summary: Add a new mentor (Admin).
 *     description: Adds a new mentor to the system. Requires admin authentication.
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
 *                 example: Dr. John Doe
 *               email:
 *                 type: string
 *                 format: email
 *                 example: john.doe@example.com
 *     responses:
 *       201:
 *         description: Mentor added successfully. Returns the mentor ID.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Mentor added successfully.
 *                 mentorId:
 *                   type: string
 *                   example: 60f8a7b2e9d3f4125c8b7a9e
 *       400:
 *         description: Invalid request parameters.
 *       401:
 *         description: Unauthorized - Admin authentication required.
 *       409:
 *         description: Mentor with this email already exists.
 *       500:
 *         description: Server error.
 */
router.post('/add-mentor', [
    check('name').notEmpty().withMessage('Name is required'),
    check('email').isEmail().withMessage('Invalid email address'),
], authenticate, authorize(['admin']), async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, email } = req.body;

    try {
        const existingMentor = await Mentor.findOne({ email });
        if (existingMentor) {
            const error = new Error('Mentor with this email already exists.');
            error.statusCode = 409;
            return next(error);
        }

        const generatedPassword = Math.random().toString(36).slice(-8);
        const hashedPassword = await bcrypt.hash(generatedPassword, 10);

        const newMentor = new Mentor({
            name,
            email,
            password: hashedPassword
        });

        const savedMentor = await newMentor.save();

        await sendMentorRegistrationEmail(email, generatedPassword);

        res.status(201).json({ message: 'Mentor added successfully.', mentorId: savedMentor._id });

    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});

// Function to send mentor registration email
async function sendMentorRegistrationEmail(toEmail, password) {
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
        subject: 'Welcome to the Project Portal (Mentor)!',
        html: `<p>Dear Mentor,</p><p>You have been registered as a mentor on the Real Time Project Portal.</p><p>Your auto-generated password is: <strong>${password}</strong></p><p>Please log in and you can change your password in your profile section.</p><p>Best regards,<br>The Project Portal Team</p>`
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Mentor registration email sent to ${toEmail}`);
    } catch (error) {
        console.error('Error sending mentor registration email:', error);
    }
}

/**
 * @swagger
 * /admin/update-mentor/{mentorId}:
 *   put:
 *     summary: Update an existing mentor (Admin).
 *     description: Updates the details of an existing mentor. Requires admin authentication.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: mentorId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the mentor to update.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 example: Dr. John Doe Updated
 *               email:
 *                 type: string
 *                 format: email
 *                 example: john.updated@example.com
 *     responses:
 *       200:
 *         description: Mentor updated successfully. Returns the updated mentor details.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Mentor updated successfully.
 *                 mentor:
 *                   type: object
 *                   properties:
 *                     _id:
 *                       type: string
 *                     name:
 *                       type: string
 *                     email:
 *                       type: string
 *       401:
 *         description: Unauthorized - Admin authentication required.
 *       404:
 *         description: Mentor not found.
 */
router.put('/update-mentor/:mentorId', authenticate, authorize(['admin']), async (req, res, next) => {
    const { mentorId } = req.params;
    const { name, email } = req.body;

    try {
        const mentor = await Mentor.findByIdAndUpdate(
            mentorId,
            { name, email },
            { new: true, runValidators: true }
        );
        if (!mentor) {
            const error = new Error('Mentor not found.');
            error.statusCode = 404;
            return next(error);
        }
        res.json({ message: 'Mentor updated successfully.', mentor });
    } catch (error) {
        error.statusCode = 500;
        return next(error);
    }
});

/**
 * @swagger
 * /admin/delete-mentor/{mentorId}:
 *   delete:
 *     summary: Delete a mentor (Admin).
 *     description: Deletes an existing mentor from the system. Requires admin authentication.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: mentorId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID of the mentor to delete.
 *     responses:
 *       200:
 *         description: Mentor deleted successfully. Returns a success message.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Mentor deleted successfully.
 *       401:
 *         description: Unauthorized - Admin authentication required.
 *       404:
 *         description: Mentor not found.
 *       500:
 *         description: Server error.
 */
router.delete('/delete-mentor/:mentorId', authenticate, authorize(['admin']), async (req, res, next) => {
    const { mentorId } = req.params;
    try {
        const mentor = await Mentor.findByIdAndDelete(mentorId);
        if (!mentor) {
            const error = new Error('Mentor not found.');
            error.statusCode = 404;
            return next(error);
        }
        res.json({ message: 'Mentor deleted successfully.' });
    } catch (error) {
        error.statusCode = 500;
        return next(error);
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

module.exports = router;