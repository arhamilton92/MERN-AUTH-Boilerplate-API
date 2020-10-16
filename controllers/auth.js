
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt');
const _ = require('lodash');
const mongoose = require('mongoose');
const { OAuth2Client } = require('google-auth-library');
// sendgrid
const config = require('config');
const sgMail = require('@sendgrid/mail');
const user = require('../models/user');
sgMail.setApiKey(config.sendGridAPIKey);


exports.signup = (req, res) => {
    const { name, email, password } = req.body;

    User.findOne({ email }).exec((err, user) => {
        if (user) {
            return res.status(400).json({
                error: 'Email is taken'
            });
        }

        const token = jwt.sign({ name, email, password }, config.jwtAccountActivation, { expiresIn: '30m' });

        const emailData = {
            from: config.emailFrom,
            to: config.emailTo,
            subject: `Account activation link`,
            html: `
                <h1>Please use the following link to activate your account</h1>
                <p>${config.clientURL}/auth/activate/${token}</p>
                <hr />
                <p>This email may contain sensetive information</p>
                <p>${config.clientURL}</p>
            `
        };

        sgMail
            .send(emailData)
            .then(sent => {
                // console.log('SIGNUP EMAIL SENT', sent)
                return res.json({
                    message: `Email has been sent to ${email}. Follow the instruction to activate your account`
                });
            })
            .catch(err => {
                // console.log('SIGNUP EMAIL SENT ERROR', err)
                return res.json({
                    message: err.message
                });
            });
    });
};

exports.accountActivation = (req, res) => {
    const { token } = req.body;

    if (token) {
        jwt.verify(token, config.jwtAccountActivation, function(err, decoded) {
            if (err) {
                console.log('JWT VERIFY IN ACCOUNT ACTIVATION ERROR', err);
                return res.status(401).json({
                    error: 'Expired link. Signup again'
                });
            }

            const { name, email, password } = jwt.decode(token);

            const user = new User({ name, email, password });

            user.save((err, user) => {
                if (err) {
                    console.log('SAVE USER IN ACCOUNT ACTIVATION ERROR', err);
                    return res.status(401).json({
                        error: 'Error saving user in database. Try signup again'
                    });
                }
                return res.json({
                    message: 'Signup success. Please signin.'
                });
            });
        });
    } else {
        return res.json({
            message: 'Something went wrong. Try again.'
        });
    }
};

exports.signin = (req, res) => {
    const { email, password } = req.body;
    // check if user exist
    User.findOne({ email }).exec((err, user) => {
        if (err || !user) {
            return res.status(400).json({
                error: 'User with that email does not exist. Please signup'
            });
        }
        // authenticate
        if (!user.authenticate(password)) {
            return res.status(400).json({
                error: 'Email and password do not match'
            });
        }
        // generate a token and send to client
        const token = jwt.sign({ _id: user._id, name: user.name }, config.jwtSecret, { expiresIn: '7d' });
        const { _id, name, email, role } = user;

        return res.json({
            token,
            user: { _id, name, email, role }
        });
    });
};

exports.requireSignin = expressJwt({
    secret: config.jwtSecret, // req.user._id
    algorithms: ['sha1', 'RS256', 'HS256'],
})

exports.requireAdmin = (req, res, next) => {
    User.findById(req.user._id).exec((err, user) => {
        if (err || !user) {
            return res.status(400).json({
                error: 'User not found'
            })
        }
        //
        if(user.role !== 'admin') {
            return res.status(400).json({
                error: 'Not Authorized'
            });
        }
        //
        req.profile = user
        next()
    })
}

exports.forgotPassword = (req, res) => {
    const { email } = req.body
    //find User with provided email. 
    User.findOne({ email }, (err, user) => {
        if(err || !user) {
            return res.status(400).json({
                error: 'User with that email does not exist.'
            })
        }
        // create the token the User will need to retrive from email.
        const token = jwt.sign({ _id: user._id, name: user.name }, config.jwtResetPassword, { expiresIn: '30m' });
        // set the email data.
        const emailData = {
            from: config.emailFrom,
            to: config.emailTo,
            subject: `Account activation link`,
            html: `
                <h1>Please use the following link to reset your password.</h1>
                <p>${config.clientURL}/auth/resetpassword/${token}</p>
                <hr />
                <p>This email may contain sensetive information</p>
                <p>${config.clientURL}</p>
            `
        };
        // set ResetPasswordLink in User model to the token.
        return user.updateOne({ resetPasswordLink: token }, (err, success) => {
            if(err) {
                console.log('RESET PASSWORD LINK ERROR', err)
                return res.status(400).json({
                    error: 'Database connection error - User Password Request'
                })
            } else {
                //send email
                sgMail
                .send(emailData)
                .then(sent => {
                    // console.log('SIGNUP EMAIL SENT', sent)
                    return res.json({
                        message: `Email has been sent to ${email}. Follow the instruction to activate your account`
                    });
                })
                .catch(err => {
                    // console.log('SIGNUP EMAIL SENT ERROR', err)
                    return res.json({
                        message: err.message
                    });
                });
            }
        })
    })
}

exports.resetPassword = (req, res) => {
    const { resetPasswordLink, newPassword } = req.body

    if(resetPasswordLink) {
        jwt.verify(resetPasswordLink, config.jwtResetPassword, function(err, decoded) {
            if(err) {
                return res.status(400).json({
                    error: 'Expired Link. Please request another.'
                });
            }

            User.findOne({ resetPasswordLink }, (err, user) => {
                console.log(resetPasswordLink)
                if(err || !user) {
                    return res.status(400).json({
                        error: 'Something went wrong. Please Try again later.'
                    })
                }
                const updatedFields = {
                    password: newPassword,
                    resetPasswordLink: ''
                }

                user = _.extend(user, updatedFields)

                user.save((err, result) => {
                    if(err) {
                        return res.status(400).json({
                            error: 'User reset password failure. Please retry.'
                        });
                    }
                    res.json({
                        message: `Success! Please login with your new password.`
                    })
                })
            })
        })
    }
}

const client = new OAuth2Client(config.googleClientId);
exports.googleLogin = (req, res) => {
    const { idToken } = req.body;

    client.verifyIdToken({ idToken, audience: config.googleClientId }).then(response => {
        // console.log('GOOGLE LOGIN RESPONSE',response)
        const { email_verified, name, email } = response.payload;
        if (email_verified) {
            User.findOne({ email }).exec((err, user) => {
                if (user) {
                    const token = jwt.sign({ _id: user._id }, config.jwtSecret, { expiresIn: '7d' });
                    const { _id, email, name, role } = user;
                    return res.json({
                        token,
                        user: { _id, email, name, role }
                    });
                } else {
                    let password = email + config.jwtSecret;
                    user = new User({ name, email, password });
                    user.save((err, data) => {
                        if (err) {
                            console.log('ERROR GOOGLE LOGIN ON USER SAVE', err);
                            return res.status(400).json({
                                error: 'User signup failed with google'
                            });
                        }
                        const token = jwt.sign({ _id: data._id }, config.jwtSecret, { expiresIn: '7d' });
                        const { _id, email, name, role } = data;
                        return res.json({
                            token,
                            user: { _id, email, name, role }
                        });
                    });
                }
            });
        } else {
            return res.status(400).json({
                error: 'Google login failed. Try again'
            });
        }
    });
};