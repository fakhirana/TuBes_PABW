const bcrypt = require("bcryptjs");
const { validateAuthorization } = require("../utils/Authorization");
const { validateUser, generateToken } = require("../utils/validateUser");
const { queryPromise } = require("../utils/promise");

exports.getAllUsers = async (req, res) => {
    const authorizedUser = validateAuthorization(req.headers.authorization);
    if (!authorizedUser) {
        return res.status(401).send("Unauthorized: Invalid or missing token");
    }
    const token = req.headers.authorization.split(" ")[1];
    const user = validateUser(token);
    if (!user) {
        return res.status(401).send("Invalid token");
    }

    try {
        const userQuery = "SELECT * FROM user WHERE id = ?";
        const rows = await queryPromise(userQuery, [user.id]);
        const data = rows[0];
        if (data.role !== "admin") {
            return res.status(401).send("Unauthorized: Only admins can get users");
        }

        const allUsersQuery = "SELECT * FROM user";
        const allUsers = await queryPromise(allUsersQuery);
        res.status(200).json(allUsers);
    } catch (err) {
        console.error("Database query failed: ", err);
        res.status(500).send({ error: "Database query failed" });
    }
};

exports.getUserById = async (req, res) => {
    const query = `SELECT * FROM user WHERE id = ?`;
    try {
        const rows = await queryPromise(query, [req.params.id]);
        if (rows.length === 0) {
            return res.status(404).send({ error: "User not found" });
        }
        res.status(200).json(rows[0]);
    } catch (err) {
        console.error("Database query failed: ", err);
        res.status(500).send({ error: "Database query failed" });
    }
};

exports.Register = async (req, res) => {
    const { email, full_name, username, password, phone, action } = req.body;

    try {
        const existingUserQuery = `SELECT * FROM user WHERE username = ?`;
        const rows = await queryPromise(existingUserQuery, [username]);

        if (action === "check") {
            if (rows.length > 0) {
                return res.status(400).send({ error: "username is already in use" });
            } else {
                return res.status(200).send({ message: "username is available" });
            }
        }

        if (rows.length > 0) {
            return res.status(400).send({ error: "username is already in use" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const query =
            "INSERT INTO user (email, full_name, username, password, phone, role) VALUES (?, ?, ?, ?, ?, 'user')";
        await queryPromise(query, [
            email,
            full_name,
            username,
            hashedPassword,
            phone,
        ]);
        res.status(201).send({ message: "Registered successfully" });
    } catch (err) {
        console.error("Database query failed: ", err);
        res.status(500).send({ error: "Database query failed" });
    }
};

exports.Login = async (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM user WHERE username = ?`;
    try {
        const rows = await queryPromise(query, [username]);
        if (rows.length === 0) {
            console.error("Username atau password tidak valid");
            return res.status(401).send({ error: "Username atau password tidak valid" });
        }

        const user = rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).send({ error: "Username atau password tidak valid" });
        }

        const token = generateToken(user.id);
        res.status(200).send({ token });
    } catch (err) {
        console.error("Kueri database gagal: ", err);
        res.status(500).send({ error: "Kueri database gagal" });
    }
};



exports.getUserData = async (req, res) => {
    if (!validateAuthorization(req.headers.authorization)) {
        return res.status(401).send({ error: "Authorization header is missing or invalid" });
    }

    const token = req.headers.authorization.split(' ')[1];
    const user = validateUser(token);
    if (!user) {
        return res.status(401).send({ error: "Invalid token" });
    }

    try {
        const query = `SELECT email, full_name, phone, username, avatar FROM user WHERE id = ?`;
        const rows = await queryPromise(query, [user.id]);
        if (rows.length === 0) {
            return res.status(404).send({ error: "User not found" });
        }

        const userData = rows[0];
        userData.avatar = userData.avatar.toString('base64');

        res.status(200).send(userData);
    } catch (err) {
        console.error("Failed to get user data: ", err);
        res.status(500).send({ error: "Failed to get user data" });
    }
};

exports.editProfile = async (req, res) => {
    let { username, full_name, phone, password } = req.body;
    const authorizedUser = validateAuthorization(req.headers.authorization);
    if (!authorizedUser) {
        return res.status(401).send("Unauthorized: Invalid or missing token");
    }
    const token = req.headers.authorization.split(" ")[1];
    const user = validateUser(token);
    if (!user) {
        return res.status(401).send("Invalid token");
    }

    try {
        const userQuery = `SELECT * FROM user WHERE id = ?`;
        const rows = await queryPromise(userQuery, [user.id]);
        const data = rows[0];

        const hashedPassword = password
            ? await bcrypt.hash(password, 10)
            : data.password;
        username = username || data.username;
        full_name = full_name || data.full_name;
        phone = phone || data.phone;

        const updateQuery =
            "UPDATE user SET username = ?, full_name = ?, phone = ?, password = ? WHERE id = ?";
        await queryPromise(updateQuery, [
            username,
            full_name,
            phone,
            hashedPassword,
            user.id,
        ]);
        res.status(200).send({ message: "Profile updated successfully" });
    } catch (err) {
        console.error("Database query failed: ", err);
        res.status(500).send({ error: "Database query failed" });
    }
};

exports.deleteUserById = async (req, res) => {
    const authorizedUser = validateAuthorization(req.headers.authorization);
    if (!authorizedUser) {
        return res.status(401).send("Unauthorized: Invalid or missing token");
    }
    const token = req.headers.authorization.split(" ")[1];
    const user = validateUser(token);
    if (!user) {
        return res.status(401).send("Invalid token");
    }

    try {
        const userQuery = "SELECT * FROM user WHERE id = ?";
        const rows = await queryPromise(userQuery, [user.id]);
        const data = rows[0];

        if (data.role !== "admin") {
            return res.status(401).send("Unauthorized: Only admins can delete users");
        }

        const deleteQuery = "DELETE FROM user WHERE id = ?";
        const result = await queryPromise(deleteQuery, [req.params.id]);

        if (result.affectedRows === 0) {
            return res.status(404).send({ message: "User not found" });
        }
        res
            .status(200)
            .send({ message: `User with id: ${req.params.id} deleted successfully` });
    } catch (err) {
        console.error("Database query failed: ", err);
        res.status(500).send({ error: "Database query failed" });
    }
};

exports.resetPassword = async (req, res) => {
    const { username, newPassword } = req.body;
    try {
        const userQuery = "SELECT * FROM user WHERE username = ?";
        const rows = await queryPromise(userQuery, [username]);
        if (!rows) {
            return res.send("username Not Found")
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10)
        const queryUpdate = `UPDATE user SET password = ? WHERE username = ?`
        await queryPromise(queryUpdate, [hashedPassword, username])
        res.status(200).send({ message: "Password updated successfully" });
    } catch (err) {
        console.error("Database query failed: ", err);
        res.status(500).send({ error: "Database query failed" });
    }
}