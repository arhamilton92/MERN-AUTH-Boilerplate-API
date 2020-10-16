const { check } = require('express-validator');

exports.userSignupValidator = [
    check('name')
        .not()
        .isEmpty()
        .withMessage('Name is required'),
    check('email')
        .isEmail()
        .withMessage('Valid email address is required.'),
    check('password')
        .isLength({ min: 6 })
        .withMessage('password must be at least 6 characters long.')
]

exports.userSigninValidator = [
    check('email')
        .isEmail()
        .withMessage('Valid email address is required.'),
    check('password')
        .isLength({ min: 6 })
        .withMessage('password must be at least 6 characters long.')
]

exports.forgotPasswordValidator = [
    check('email')
        .not()
        .isEmpty()
        .isEmail()
        .withMessage('Valid email address is required.'),
]

exports.resetPasswordValidator = [
    check('newPassword')
        .not()
        .isEmpty()
        .isLength({ min: 6 })
        .withMessage('password must be at least 6 characters long.')
]