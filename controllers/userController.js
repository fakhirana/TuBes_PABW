const connection = require("../config/database");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { validateAuthorization } = require("../utils/Authorization");
const { validateUser } = require("../utils/validateUser");

exports.getAllUsers = (req, res) => {
    connection.query("SELECT * FROM user", (err, rows) => {
        if (err) {
            res.status(500).send({ error: "Database query failed" });
        } else {
            res.status(200).json(rows);
        }
    });
};

exports.getUserById = (req, res) => {
    connection.query(
        "SELECT * FROM user WHERE id = ?",
        [req.params.id],
        (err, rows) => {
        if (err) {
            res.status(500).send({ error: "Database query failed" });
        } else if (rows.length === 0) {
            res.status(404).send({ error: "User not found" });
        } else {
            res.status(200).json(rows[0]);
        }
        }
    );
};

const UserRole = {
    ADMIN: 'admin',
    USER: 'user',
};

exports.Register = async (req, res) => {
    const { full_name, email, username, password, phone } = req.body;
    const role = req.body.role?.toLowerCase();

    if (role && !Object.values(UserRole).includes(role)) {
    return res.status(400).send({ error: 'Invalid role. Valid roles: admin, user' });
    }

    try {
        const [existingUser] = await connection.promise().query("SELECT * FROM user WHERE email = ?", [email]);
        if (existingUser.length > 0) {
        return res.status(400).send({ error: 'Email is already in use' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const insertRole = role || UserRole.USER;

        const query = "INSERT INTO user (full_name, email, username, password, phone, role) VALUES (?, ?, ?, ?, ?, ?)";
        await connection.promise().query(query, [full_namename, email, username, hashedPassword, phone, insertRole]);

        res.status(201).send({ message: 'Registered successfully' });
    } catch (error) {
        console.error('Registration failed:', error);
        res.status(500).send({ error: 'Registration failed' });
    }
    };

    exports.Login = async (req, res) => {
    try {
        const [rows] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [req.body.username]);
        if (rows.length === 0) {
        return res.status(401).send({ error: "Invalid username or password" });
        }

        const user = rows[0];
        const match = await bcrypt.compare(req.body.password, user.password);
        if (!match) {
        return res.status(401).send({ error: "Invalid username or password" });
        }

        const token = jwt.sign({ id: user.id }, "assalamualaikumwarohmatullahiwabarokatuh");
        res.status(200).send({ token });
    } catch (error) {
        console.error('Login failed:', error);
        res.status(500).send({ error: 'Login failed' });
    }
    };

    exports.editProfile = async (req, res) => {
    const {full_name, password } = req.body;
    const authorizedUser = validateAuthorization(req.headers.authorization);
    if (!authorizedUser) {
        return res.status(401).send("Unauthorized: Invalid or missing token");
    }

    try {
        const token = req.headers.authorization.split(" ")[1];
        const user = validateUser(token);
        if (!user) {
        return res.status(401).send("Invalid token");
        }

        const [rows] = await connection.promise().query("SELECT * FROM user WHERE id = ?", [user.id]);
        if (rows.length === 0) {
        return res.status(404).send({ error: "User not found" });
        }

        const data = rows[0];
        const hashedPassword = password ? await bcrypt.hash(password, 10) : data.password;
        const newName =full_name || data.name;
        const query = "UPDATE user SETfull_name = ?, password = ? WHERE id = ?";
        await connection.promise().query(query, [newName, hashedPassword, user.id]);

        res.status(200).send({ message: "Profile updated successfully" });
    } catch (error) {
        console.error('Profile update failed:', error);
        res.status(500).send({ error: 'Profile update failed' });
    }
    };

    exports.deleteUserById = async (req, res) => {
    const authorizedUser = validateAuthorization(req.headers.authorization);
    if (!authorizedUser) {
        return res.status(401).send("Unauthorized: Invalid or missing token");
    }

    try {
        const token = req.headers.authorization.split(" ")[1];
        const user = validateUser(token);
        if (!user) {
        return res.status(401).send("Invalid token");
        }

        const [rows] = await connection.promise().query("SELECT * FROM user WHERE id = ?", [user.id]);
        if (rows.length === 0 || rows[0].role !== UserRole.ADMIN) {
        return res.status(401).send("You are not authorized to perform this action");
        }

        const [result] = await connection.promise().query("DELETE FROM user WHERE id = ?", [req.params.id]);
        if (result.affectedRows === 0) {
        return res.status(404).send({ error: "User not found" });
        }

        res.status(200).send({ message: User with ID ${req.params.id} deleted successfully });
    } catch (error) {
        console.error('Delete user failed:', error);
        res.status(500).send({ error: 'Delete user failed' });
    }
    };