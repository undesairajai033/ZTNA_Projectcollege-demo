console.log("CURRENT FOLDER:", __dirname);

const express = require("express");
const path = require("path");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require("@simplewebauthn/server");

const app = express();
const PORT = 3000;
const SECRET_KEY = "mysecretkey";
const rpName = "ZTNA College Portal";
const rpID = "localhost";
const origin = "http://localhost:3000";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

/* ---------------- PAGE ROUTES ---------------- */
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "login.html"));
});

/* ---------------- MAIL SETUP ---------------- */
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "sairjunde061@gmail.com",
        pass: "abcdefghijklmnop"
    }
});

transporter.verify((error) => {
    if (error) {
        console.log("Mail Error:", error);
    } else {
        console.log("Mail Server Ready");
    }
});

/* ---------------- USERS ---------------- */
const users = [
    {
        email: "sairajunde061@gmail.com",
        password: "SAIraj@2506",
        role: "student",
        name: "Sai ",
        department: "AI&DS",
        phone: "9137751268",
        photo: "/images/student.jpg"
    },
    {
        email: "sairajunde07@gmail.com",
        password: "4321",
        role: "faculty",
        name: "Prof. Sairaj Unde",
        department: "AI&DS",
        phone: "9137751268",
        subject: "Machine Learning",
        photo: "/images/faculty.jpg"
    },
    {
        email: "unde.sairaj.ai033@gmail.com",
        password: "1234",
        role: "admin",
        name: "Admin",
        department: "Administration",
        phone: "9137751268",
        photo: "/images/admin.jpg"
    }
];

/* ---------------- STORAGE ---------------- */
let otpStore = {};
let loginHistory = {};
let requestData = {};
let loginLogs = [];
let biometricUsers = {};
let biometricChallenges = {};

/* ---------------- HELPERS ---------------- */
function normalizeEmail(email) {
    return (email || "").trim().toLowerCase();
}

function normalizePassword(password) {
    return (password || "").trim();
}

function getAdminBiometricKey(email) {
    return `${normalizeEmail(email)}_admin`;
}

function getClientIP(req) {
    let ip =
        req.headers["x-forwarded-for"] ||
        req.socket.remoteAddress ||
        req.ip ||
        "unknown";

    if (typeof ip === "string" && ip.includes(",")) {
        ip = ip.split(",")[0].trim();
    }

    if (ip === "::1" || ip === "::ffff:127.0.0.1") {
        ip = "127.0.0.1";
    }

    return ip;
}

/* ---------------- JWT ---------------- */
function verifyToken(req, res, next) {
    const token = req.headers["authorization"];

    if (!token) {
        return res.status(403).json({ message: "No token provided" });
    }

    try {
        req.user = jwt.verify(token, SECRET_KEY);
        next();
    } catch (error) {
        return res.status(401).json({ message: "Invalid token" });
    }
}

function checkRole(role) {
    return (req, res, next) => {
        if (req.user.role === role) {
            next();
        } else {
            return res.status(403).json({ message: "Access Denied" });
        }
    };
}

/* ---------------- RISK CONTROL ---------------- */
function detectRisk(req, res, next) {
    const ip = getClientIP(req);
    const now = Date.now();

    if (!requestData[ip]) {
        requestData[ip] = { count: 1, time: now };
    } else {
        requestData[ip].count++;
    }

    const diff = (now - requestData[ip].time) / 1000;

    if (requestData[ip].count > 5 && diff < 10) {
        return res.status(429).json({
            success: false,
            message: "Too many requests. Wait 10 seconds"
        });
    }

    if (diff > 10) {
        requestData[ip] = { count: 1, time: now };
    }

    next();
}

app.use(detectRisk);

/* ---------------- STUDENTS ---------------- */
let students = [
    { id: 1, name: "Sakshi Sanas", email: "student1@gmail.com", attendance: 90, marks: { Maths: 85, AI: 92, DS: 88 } },
    { id: 2, name: "Sairaj Unde", email: "student2@gmail.com", attendance: 85, marks: { Maths: 78, AI: 80, DS: 82 } },
    { id: 3, name: "Raj Patil", email: "student3@gmail.com", attendance: 95, marks: { Maths: 92, AI: 95, DS: 90 } },
    { id: 4, name: "Aryan Kadam", email: "student4@gmail.com", attendance: 77, marks: { Maths: 99, AI: 76, DS: 72 } },
    { id: 5, name: "Saniya Dsouza", email: "student5@gmail.com", attendance: 50, marks: { Maths: 99, AI: 90, DS: 90 } },
    { id: 6, name: "Tejas Sabbani", email: "student6@gmail.com", attendance: 89, marks: { Maths: 88, AI: 65, DS: 80 } },
    { id: 7, name: "Mira Rajput", email: "student7@gmail.com", attendance: 90, marks: { Maths: 92, AI: 65, DS: 70 } }
];

/* ---------------- LOGIN ---------------- */
app.post("/api/login", (req, res) => {
    const rawEmail = req.body.email;
    const rawPassword = req.body.password;
    const device = req.body.device;
    const now = Date.now();

    const email = normalizeEmail(rawEmail);
    const password = normalizePassword(rawPassword);

    console.log("LOGIN REQUEST:", { email, password, device });

    if (!email || !password) {
        return res.json({
            success: false,
            message: "Email and password are required"
        });
    }

    if (!loginHistory[email]) {
        loginHistory[email] = [];
    }

    loginHistory[email].push(now);

    if (loginHistory[email].length > 5) {
        loginHistory[email].shift();
    }

    if (loginHistory[email].length >= 3) {
        const diff = (now - loginHistory[email][loginHistory[email].length - 3]) / 1000;

        if (diff < 10) {
            return res.json({
                success: false,
                message: "Suspicious activity detected. Wait 10 seconds"
            });
        }
    }

    const user = users.find(
        (u) =>
            normalizeEmail(u.email) === email &&
            normalizePassword(u.password) === password
    );

    console.log("FOUND USER:", user);

    if (!user) {
        return res.json({
            success: false,
            message: "Invalid credentials"
        });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);

    otpStore[email] = {
        otp,
        role: user.role,
        time: Date.now()
    };

    loginLogs.push({
        email,
        role: user.role,
        ip: getClientIP(req),
        device: device || "Unknown Device",
        time: new Date().toLocaleString()
    });

    transporter.sendMail(
        {
            from: "sairajunde061@gmail.com",
            to: email,
            subject: "Your OTP for Login",
            text: `Your OTP is ${otp}`
        },
        (err, info) => {
            if (err) {
                console.log("MAIL ERROR:", err);
                console.log("BACKUP OTP:", otp);

                return res.json({
                    success: true,
                    otpRequired: true,
                    message: "Email failed, check terminal OTP",
                    role: user.role
                });
            }

            console.log("MAIL SENT:", info.response);
            console.log("BACKUP OTP:", otp);

            return res.json({
                success: true,
                otpRequired: true,
                message: "OTP sent to your email",
                role: user.role
            });
        }
    );
});

/* ---------------- VERIFY OTP ---------------- */
app.post("/api/verify-otp", (req, res) => {
    const email = normalizeEmail(req.body.email);
    const otp = (req.body.otp || "").trim();

    if (!email || !otp) {
        return res.json({
            success: false,
            message: "Email and OTP are required"
        });
    }

    if (!otpStore[email]) {
        return res.json({
            success: false,
            message: "OTP not found"
        });
    }

    const data = otpStore[email];

    if ((Date.now() - data.time) / 1000 > 30) {
        delete otpStore[email];
        return res.json({
            success: false,
            message: "OTP expired"
        });
    }

    if (String(data.otp) === otp) {
        const token = jwt.sign(
            { email, role: data.role },
            SECRET_KEY,
            { expiresIn: "60s" }
        );

        delete otpStore[email];

        return res.json({
            success: true,
            token,
            role: data.role
        });
    }

    return res.json({
        success: false,
        message: "Invalid OTP"
    });
});

/* ---------------- RESEND OTP ---------------- */
app.post("/api/resend-otp", (req, res) => {
    const email = normalizeEmail(req.body.email);

    if (!email) {
        return res.json({
            success: false,
            message: "Email is required"
        });
    }

    if (!otpStore[email]) {
        return res.json({
            success: false,
            message: "Login first"
        });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);

    otpStore[email].otp = otp;
    otpStore[email].time = Date.now();

    transporter.sendMail(
        {
            from: "sairajunde061@gmail.com",
            to: email,
            subject: "Resend OTP",
            text: `New OTP is ${otp}`
        },
        (err, info) => {
            if (err) {
                console.log("RESEND MAIL ERROR:", err);
                console.log("RESENT BACKUP OTP:", otp);

                return res.json({
                    success: true,
                    message: "Email failed, check terminal OTP"
                });
            }

            console.log("RESENT MAIL:", info.response);
            console.log("RESENT BACKUP OTP:", otp);

            return res.json({
                success: true,
                message: "OTP resent to your email"
            });
        }
    );
});

/* ---------------- PROFILE API ---------------- */
app.get("/api/profile", verifyToken, (req, res) => {
    const email = req.user.email;
    const role = req.user.role;

    const user = users.find(
        (u) => normalizeEmail(u.email) === normalizeEmail(email) && u.role === role
    );

    if (!user) {
        return res.status(404).json({ message: "Profile not found" });
    }

    res.json({
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        phone: user.phone,
        subject: user.subject || "",
        photo: user.photo
    });
});

/* ---------------- BIOMETRIC REGISTER OPTIONS (ADMIN ONLY) ---------------- */
app.post("/api/biometric/register-options", verifyToken, async (req, res) => {
    try {
        const email = req.user.email;
        const role = req.user.role;

        if (role !== "admin") {
            return res.status(403).json({
                message: "Biometric is enabled only for admin"
            });
        }

        const biometricKey = getAdminBiometricKey(email);
        const userID = new TextEncoder().encode(biometricKey);

        const options = await generateRegistrationOptions({
            rpName,
            rpID,
            userName: biometricKey,
            userID,
            userDisplayName: "Admin Biometric",
            timeout: 60000,
            attestationType: "none",
            authenticatorSelection: {
                authenticatorAttachment: "platform",
                residentKey: "preferred",
                userVerification: "preferred"
            },
            excludeCredentials: biometricUsers[biometricKey]
                ? [
                    {
                        id: biometricUsers[biometricKey].credentialID,
                        transports: biometricUsers[biometricKey].transports || ["internal"]
                    }
                ]
                : []
        });

        biometricChallenges[biometricKey] = options.challenge;
        return res.json(options);
    } catch (error) {
        console.log("REGISTER OPTIONS ERROR:", error);
        return res.status(500).json({
            message: "Failed to generate registration options"
        });
    }
});

/* ---------------- BIOMETRIC REGISTER VERIFY (ADMIN ONLY) ---------------- */
app.post("/api/biometric/register-verify", verifyToken, async (req, res) => {
    try {
        const email = req.user.email;
        const role = req.user.role;

        if (role !== "admin") {
            return res.status(403).json({
                success: false,
                message: "Biometric is enabled only for admin"
            });
        }

        const biometricKey = getAdminBiometricKey(email);
        const body = req.body;
        const expectedChallenge = biometricChallenges[biometricKey];

        const verification = await verifyRegistrationResponse({
            response: body,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID
        });

        const { verified, registrationInfo } = verification;

        if (!verified || !registrationInfo) {
            return res.json({
                success: false,
                message: "Biometric registration failed"
            });
        }

        const { credential } = registrationInfo;

        biometricUsers[biometricKey] = {
            credentialID: credential.id,
            publicKey: credential.publicKey,
            counter: credential.counter,
            transports: body.response.transports || []
        };

        delete biometricChallenges[biometricKey];

        return res.json({
            success: true,
            message: "Biometric enabled successfully"
        });
    } catch (error) {
        console.log("REGISTER VERIFY ERROR:", error);
        return res.status(500).json({
            success: false,
            message: "Biometric verification failed"
        });
    }
});

/* ---------------- BIOMETRIC LOGIN OPTIONS (ADMIN ONLY) ---------------- */
app.post("/api/biometric/login-options", async (req, res) => {
    try {
        const email = normalizeEmail(req.body.email);
        const biometricKey = getAdminBiometricKey(email);

        if (!biometricUsers[biometricKey]) {
            return res.json({
                success: false,
                message: "Admin biometric not enabled for this account"
            });
        }

        const userDevice = biometricUsers[biometricKey];

        const options = await generateAuthenticationOptions({
            rpID,
            userVerification: "preferred",
            allowCredentials: [
                {
                    id: userDevice.credentialID,
                    transports: userDevice.transports || ["internal"]
                }
            ]
        });

        biometricChallenges[biometricKey] = options.challenge;

        return res.json({
            success: true,
            options
        });
    } catch (error) {
        console.log("LOGIN OPTIONS ERROR:", error);
        return res.status(500).json({
            success: false,
            message: "Failed to generate biometric login options"
        });
    }
});

/* ---------------- BIOMETRIC LOGIN VERIFY (ADMIN ONLY) ---------------- */
app.post("/api/biometric/login-verify", async (req, res) => {
    try {
        const email = normalizeEmail(req.body.email);
        const body = req.body.credential;
        const biometricKey = getAdminBiometricKey(email);
        const userDevice = biometricUsers[biometricKey];

        if (!userDevice) {
            return res.json({
                success: false,
                message: "No admin biometric found for this user"
            });
        }

        const expectedChallenge = biometricChallenges[biometricKey];

        const verification = await verifyAuthenticationResponse({
            response: body,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            credential: {
                id: userDevice.credentialID,
                publicKey: userDevice.publicKey,
                counter: userDevice.counter,
                transports: userDevice.transports || ["internal"]
            }
        });

        if (!verification.verified) {
            return res.json({
                success: false,
                message: "Biometric login failed"
            });
        }

        userDevice.counter = verification.authenticationInfo.newCounter;

        const user = users.find(
            (u) => normalizeEmail(u.email) === email && u.role === "admin"
        );

        if (!user) {
            return res.json({
                success: false,
                message: "Admin user not found"
            });
        }

        const token = jwt.sign(
            { email, role: "admin" },
            SECRET_KEY,
            { expiresIn: "60s" }
        );

        delete biometricChallenges[biometricKey];

        return res.json({
            success: true,
            token,
            role: "admin"
        });
    } catch (error) {
        console.log("LOGIN VERIFY ERROR:", error);
        return res.status(500).json({
            success: false,
            message: "Biometric verification failed"
        });
    }
});

/* ---------------- LOGS ---------------- */
app.get("/api/login-logs", verifyToken, checkRole("admin"), (req, res) => {
    res.json(loginLogs);
});

/* ---------------- STUDENT APIs ---------------- */
app.get("/api/students", verifyToken, (req, res) => {
    res.json(students);
});

app.get("/api/student/:id", verifyToken, checkRole("student"), (req, res) => {
    const student = students.find((s) => s.id == req.params.id);

    if (!student) {
        return res.status(404).json({ message: "Not found" });
    }

    res.json(student);
});

app.get("/api/marks/:id", verifyToken, checkRole("student"), (req, res) => {
    const student = students.find((s) => s.id == req.params.id);

    if (!student) {
        return res.status(404).json({ message: "Not found" });
    }

    res.json({
        name: student.name,
        marks: student.marks
    });
});

/* ---------------- ADMIN ---------------- */
app.post("/api/students", verifyToken, checkRole("admin"), (req, res) => {
    const { name, email, attendance, marks } = req.body;

    const newStudent = {
        id: students.length + 1,
        name,
        email,
        attendance: Number(attendance),
        marks
    };

    students.push(newStudent);

    res.json({
        message: "Student added",
        student: newStudent
    });
});

app.delete("/api/students/:id", verifyToken, checkRole("admin"), (req, res) => {
    students = students.filter((s) => s.id != req.params.id);
    res.json({ message: "Deleted" });
});

/* ---------------- START ---------------- */
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
});