const express = require('express');
const router = express.Router();

// import controller
const { signup, accountActivation, signin, getUser, forgotPassword, resetPassword, googleLogin} = require('../controllers/auth')

// import validators
const { userSignupValidator, userSigninValidator, forgotPasswordValidator, resetPasswordValidator } = require('../validators/auth');
const { validate } = require('../validators/index');


router.post('/signup', userSignupValidator, validate, signup)
router.post('/account-activation', accountActivation)
router.post('/signin', userSigninValidator, validate, signin)
//forgot reset password
router.put('/recoverpassword', forgotPasswordValidator, validate, forgotPassword)
router.put('/resetpassword', resetPasswordValidator, validate, resetPassword)
//google and facebook
router.post('/google-login', googleLogin)


module.exports = router; // {}