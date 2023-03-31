const express = require('express');
const app = express();
var dotenv = require('dotenv').config({ path: `${__dirname}/.env` });
var LocalStorage = require('node-localstorage').LocalStorage;
LocalStorage = new LocalStorage('./scratch');
const passport = require('passport');
const passportConfig = require('./passport');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const cors = require('cors');
app.use(cookieParser());
app.use(express.json());
app.use(
  cors({
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization'],
    origin: ['https://workout-builder.netlify.app'],
  })
);

var url = process.env.MONGO_URI;

mongoose.connect(
  url,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
  () => {
    console.log('Successfully connected to database');
  }
);

const userRouter = require('./routes/User');
app.use('/user', userRouter);

const workoutRouter = require('./routes/Workout');
app.use('/workout', workoutRouter);

const PORT = process.env.PORT || 5000;

app.listen(PORT, function () {
  console.log(`Server started on port ${PORT}`);
});
