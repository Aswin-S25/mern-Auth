const mongoose = require('mongoose');
const {isEmail} = require('validator');
const bcrypt = require('bcrypt');


const userSchema = mongoose.Schema({
    email: {
        type: String,
        required: [true, 'please enter an email'],
        unique: true, lowercase: true,
        validate: [isEmail, 'please enter a valid email id']
    },
    password: {
        type: String,
        required: [true, 'please enter a password'],
        minlength: [8, 'minimum password length is 8 characters']
    }

    },
    {
        timestamps: true
    }
);

//fire a function after doc saved to db

// userSchema.post('save', (doc, next) => {
//     console.log('new user was created and saved', doc);
//     next();
// });

//fire a fucntion before doc saved to db

userSchema.pre('save', async function(next)  {
    const salt = await bcrypt.genSalt();
    console.log(salt)
    this.password = await bcrypt.hash(this.password, salt);
    console.log(this.password)
    next();
});

//static metjog to login user

userSchema.statics.login = async function(email, password) {
    const user = await this.findOne({email});
    if(user) {
        const auth = await bcrypt.compare(password, user.password);
        if(auth) {
            return user;
        }
        throw Error('incorrect password')
    }
    throw Error('incorrect email')
}

const User = mongoose.model('netninja', userSchema);

module.exports = User;