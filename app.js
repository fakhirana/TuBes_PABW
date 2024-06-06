const express = require("express");
const app = express();
const port = 3000;

const userRoutes = require('./routes/userRoute');

app.use(express.json()); //Middleware to parse JSON bodies
app.use('/user', userRoutes);

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
})