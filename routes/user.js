const express = require('express');
const router = express.Router();

// import controller
const { requireSignin, requireAdmin } = require('../controllers/auth');
const { read, update } = require('../controllers/user');

router.get('/user/:id', requireSignin, read);
router.put('/user/update', requireSignin, update);
router.put('/admin/update', requireSignin, requireAdmin, update);

module.exports = router; // {}