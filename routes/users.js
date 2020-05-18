const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

const User = require('../models/User');

//@route POST api/users
//@desc Register a user
router.post('/', [
    check('name', 'Please add a name').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('phone', 'Please enter a phone number of 10 digits').isLength({min: 10, max:10}),
    check('password', 'Please enter a password with 6 or more characters'
    ).isLength({min: 6})
], async (req, res)=>{
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({errors: errors.array()});
    }
    
    const { name, email, phone, password } = req.body;

    try {
        let user = await User.findOne({email});

        if(user) {
            return res.status(400).json({msg: 'User already exist'});
        }

        user = new User({
            name,
            email,
            phone,
            password 
        });

        const salt = await bcrypt.genSalt(10);

        user.password = await bcrypt.hash(password, salt);
        await user.save();
        const payload = {
            user: {
                id: user.id
            }
        }

        jwt.sign(payload, config.get('jwtSecret'), { 
            expiresIn: 360000
        }, (err, token)=>{
            if(err) throw err;
            res.json({token});
        });
    } catch(err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

//Get all users
router.get('/', async (req, res) => {
    try{
        const users = await User.find().select('-password');
        res.json(users);
    }catch(err){
        console.error(err.message);
        res.status(500).send('Server error');
    }
})

//Get user by id
router.get('/:id', async (req, res)=>{
    try {
       const user = await User.findById(req.params.id).select('-password');
       if(!user) return res.status(404).json({msg: 'Contact not found'});

       res.json(user);
    }catch(err) {
       console.error(err.message);
       res.status(500).send('Server error');
    }
});

//Update user by id
router.put('/:id', async (req, res) => {
    const {name, email, phone} = req.body;

    const userFields = {};
    if(name) userFields.name = name;
    if(email) userFields.email = email;
    if(phone) userFields.phone = phone;

    try {
        let user = await User.findById(req.params.id);

        if(!user) return res.status(404).json({msg: 'Contact not found'});

        user = await User.findByIdAndUpdate(req.params.id, 
            { $set: userFields},
            {new: true}).select('-password');
        res.json(user);
    } catch(err){
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

//delete user by id
router.delete("/:id", async (req, res) =>{
    try {
        let user = await User.findById(req.params.id);

        if(!user) return res.status(404).json({msg: 'Contact not found'});

        await User.findByIdAndRemove(req.params.id);
        res.json({msg: 'Contacts removed'});
    } catch(err){
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

module.exports = router;