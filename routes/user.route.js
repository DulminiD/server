let express = require('express'), router = express.Router({mergeParams: true});
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const validateRegisterInput = require("../Validation/validator");
const validateLoginInput = require("../Validation/loginvalidator");
let userSchema = require('../Model/Users');
let db= require('../Database/db');
const db1 = require("../Model");
const Role = db1.role;

//Registering the user
router.post("/register", (req, res, next) =>{
    //Validates sent data through the body. If there are they are sent to frontend
    const { errors, isValid } = validateRegisterInput(req.body);
    if(!isValid){
        return res.json(errors);
    }

    userSchema.findOne({ Email: req.body.Email }).then(user => {
        if (user) {
            return res.json({ Email: "Email already exists" });
        }
        else{
            userSchema.findOne({ Username: req.body.Username }).then(u =>{
                if(u){
                    return res.json({ Username: "Username already exists"})
                }


            if (req.body.roles) {
                const query = {name: "user"};
                //Checks if the role exists in the database and gets the id
                //Sets the id of the role and saves the data
                Role.findOne(query, (erro, roles) => {
                        if (erro) {
                            res.status(500).send({message: erro});
                            return;
                        }

                        const newUser = new userSchema({
                            FirstName: req.body.FirstName,
                            LastName: req.body.LastName,
                            Username: req.body.Username,
                            Email : req.body.Email,
                            PasswordOne : req.body.PasswordOne,
                            roles : roles._id
                        });
                        bcrypt.genSalt(10, (err, salt) => {
                            bcrypt.hash(newUser.PasswordOne, salt, (err, hash) => {
                                if (err) throw err;
                                newUser.PasswordOne = hash;
                                newUser
                                    .save()
                                    .then()
                                    .catch(err => console.log(err));
                            });
                        });
                       console.log("user registered");
                       res.json({success: true})
                    }
                );
            } else {
                Role.findOne({name: "moderator"}, (err, role) => {
                    if (err) {
                        res.status(500).send({message: err});
                        return;
                    }

                    const newUser1 = new userSchema({
                        FirstName: req.body.FirstName,
                        LastName: req.body.LastName,
                        Username: req.body.Username,
                        Email : req.body.Email,
                        PasswordOne : req.body.PasswordOne,
                        roles : role._id
                    });
                    //Encrypts the password
                    bcrypt.genSalt(10, (err, salt) => {
                        bcrypt.hash(newUser1.PasswordOne, salt, (err, hash) => {
                            if (err) throw err;
                            newUser1.PasswordOne = hash;
                            newUser1
                                .save()
                                .then()
                                .catch(err => console.log(err));
                        });
                    });
                });
            }
            });
        }


    });
});

//Logging in the user
router.post("/login", (req, res) => {
    res.header(
        "Access-Control-Allow-Headers",
        "x-access-token, Origin, Content-Type, Accept"
    );
    const { errors, isValid } = validateLoginInput(req.body);
    // Check validation
    if (!isValid) {
        return res.json(errors);
    }
    const Username = req.body.Username;
    const Password = req.body.Password;

    userSchema.findOne({ Username }).then(user => {
        // Check if user exists
        if (!user) {
            return res.json({ Username: "Username not found" });
        }
        bcrypt.compare(Password, user.PasswordOne).then(isMatch => {
            if (isMatch) {
                // User matched
                // Create JWT Payload
                const payload = {
                    id: user.id,
                    name: user.name
                };

                var token = jwt.sign(
                    payload,
                    db.secretOrKey,
                    {
                        expiresIn: 86400 // 1 year in seconds
                    },
                );

                var authorities = [];
                var query = {id : user.roles[0]};
                Role.findById(user.roles[0], null, null,(err, roles) => {

                    if(user.roles.length===1){
                        authorities.push("ROLE_" + roles.name.toUpperCase());
                    }
                    //Sends the access token, roles and the success status.
                    res.json({
                        username: user.Username,
                        success: true,
                        roles: authorities,
                        accessToken: token
                    });
                });

            } else {
                return res
                    .json({ Password: "Password incorrect" });
            }
        });
    });
});

router.post("/getOne:Username", (req, res) => {
    userSchema.findOne({ Username: req.params.Username }).then(user => {
        return res.json(user);
    });


});

//Editing the user
router.route('/edit-details:Id').put((req, res, next) => {
    console.log(req.body);
    const Email = req.body.Email;
    var newUser;
    userSchema.findOne({ Email}).then(user => {
        //Checks if the current password matches the sent password
        bcrypt.compare(req.body.CurrentPassword, user.PasswordOne).then(isMatch => {
            if (isMatch) {
                if (req.body.PasswordOne !== '') {
                    bcrypt.genSalt(10, (err, salt) => {
                        bcrypt.hash(req.body.PasswordOne, salt, (err, hash) => {
                            if (err) throw err;
                             newUser = {
                                FirstName: req.body.FirstName,
                                LastName: req.body.LastName,
                                Username: req.body.Username,
                                PasswordOne: hash
                            };
                            userSchema.findOneAndUpdate({Email:Email}, {$set: newUser}, {new:true}).then((user)=>{
                                console.log(user);
                                res.json({
                                    modifiedUser:user,
                                    success:true,
                                    passwordChanged:true
                                });
                            }).catch(err=>{
                                console.error(err);
                                res.sendStatus(500);
                            });
                        })
                    })

                } else {
                       newUser = {
                        FirstName: req.body.FirstName,
                        LastName: req.body.LastName,
                        Username: req.body.Username,
                    };
                    userSchema.findOneAndUpdate({Email:Email}, {$set: newUser}, {new:true}).then((user)=>{
                        res.json({
                            modifiedUser:user,
                            success:true,
                            passwordChanged:false
                        });
                    }).catch(err=>{
                        console.error(err);
                        res.sendStatus(500);
                    });
                }


            }
           else {
                console.log("not matched")
                res.json({Error: 'Password does not match'})
            }
        });
    });
});

//Deleting the user details
router.route('/delete-user:id').post((req,res)=> {
    userSchema.findOne({Username:req.params.id}).then(user => {
        bcrypt.compare(req.body.CurrentPassword, user.PasswordOne).then(isMatch => {
            if (isMatch) {
        userSchema.findOneAndDelete({Username: req.params.id}).then(() => {
            res.json({
                success: true
            })
        }).catch(err => {
            console.log(err);
            res.sendStatus(500);
        });}});
    });
});
module.exports = router;
