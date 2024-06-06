const connection = require("../config/database");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const { validateUser } = require("../utils/validateUser");
const { validateAuthorization } = require('../utils/Authorization');


exports.photoGetAll = (req, res) => {
    connection.query("SELECT avatar FROM user", (err, rows) => {
        if (err) {
        res.status(500).send({ error: "Database query failed" });
        } else {
        res.status(200).json(rows);
        }
    });
};

exports.uploadPhoto = (req, res) => {
    const authorizedUser = validateAuthorization(req.headers.authorization);
    if (!authorizedUser) {
        return res.status(401).send("Unauthorized: Invalid or missing token");
    }
    const token = req.headers.authorization.split(" ")[1];
    const user = validateUser(token)
    if(user == false) {
        res.status(401).send("token tidak valid!!")
        return;
    }

    const file = fs.readFileSync(`upload/${req.file.filename}`);
    const query = "UPDATE user SET avatar = ? where id = ?";
    connection.query(query, [file, user.id], (err, result) => {
        if (err) {
        res.status(500).send(err);
        } else {
        res.status(200).send(result);
        }
    });
};