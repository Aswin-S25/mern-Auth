const User = require("../models/user");
const jwt = require('jsonwebtoken') 
//handle error
const handleErrors = (err) => {

    let errors = { email: '', password: ''};


    //incorrect email

    if(err.message === 'incorrect email') {
        errors.email = 'that email is not registered';
    }
    //incorrect password
    if(err.message === 'incorrect password') {
        errors.password = 'password is wrong';
    }
    //duplicate email error
    if(err.code === 11000) {
        errors.email = 'email is already registered';
        return errors;
    }

    //validation errors
    if(err.message.includes('netninja validation failed')) {
         Object.values(err.errors).forEach(({properties}) => {
            errors[properties.path] = properties.message
         })
    }

    return errors;
}

const maxAge = 3*24*60*60;
const createToken = (id) => {
    return jwt.sign({ id }, 'net ninja secret', {
        expiresIn: maxAge
    })
}


module.exports.signup_get = (req, res) => {
    res.render('signUp');
}

module.exports.login_get = (req, res) => {
    res.render('login');
}

module.exports.signup_post = async(req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.create({ email, password });
        const token = createToken(user._id);
        res.cookie('jwt', token, {httpOnly: true, maxAge: maxAge *1000})
        res.status(200).json({ user: user._id})
    } catch (err) {
        const errors = handleErrors(err);
        res.status(400).json({errors});
    }
}

module.exports.login_post = async(req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.login(email, password);
        const token = createToken(user._id);
        res.cookie('jwt', token, {httpOnly: true, maxAge: maxAge *1000})
        res.status(200).json({user:user._id});
    } catch(err) {
        const errors = handleErrors(err);
        res.status(400).json({errors});
    }

}