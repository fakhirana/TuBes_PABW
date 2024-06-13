const express = require("express");
const cors = require('cors');
const app = express();
const port = 3000;

app.use(cors());

const userRoutes = require('./routes/userRoute');
const photoRoutes = require('./routes/photoRoutes');

app.use(express.json()); //Middleware to parse JSON bodies
app.use('/users', userRoutes);
app.use('/photos', photoRoutes);

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
})