const express = require('express');
const mongoose= require('mongoose');
const morgan = require('morgan');
const cors = require('cors');
const config = require('config');
const connectDB = require('./config/db');

const app = express();

connectDB();

// import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');

// app middlewares 
app.use(morgan('dev'));
app.use(express.json({ extended: false }))
// app.use(cors()); // allows all origins
if (config.nodeENV = 'development') {
    app.use(cors({ origin: `http://localhost:3000` }))
}

// middleware
app.use('/api', authRoutes)
app.use('/api', userRoutes)

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
    console.log(`API is running on port: ${PORT} - ${config.nodeENV}`)
})