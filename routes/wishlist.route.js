const jwt = require("jsonwebtoken");
const config = require("../Database/db");
let express = require('express');
let router = express.Router({mergeParams : true});

let wishlistSchema = require('../Model/WishList');

//Adding to the wish list
router.route('/add-to-wishlist').post((req, res, next)=>{
    wishlistSchema.create(req.body, (error,data) =>{
        if(error)
            return next(error);
        else
            return res.json(data);
    })
});
//Check if an wish list is there for the user ID
//The access tokem is decrypted and the login is verified
router.route('/check-product:userId').post((req, res, next) => {
    let token = req.headers["x-access-token"];
    if (!token) {
        res.status(403).send({ message: "No token provided!" });
    }
    jwt.verify(token, config.secretOrKey, (err, decoded) => {
        if (err) {
            res.status(401).send({ message: "Unauthorized!" });
        }else{
            if(decoded.id === req.params.userId){
                var query = {UserId : req.params.userId};
                wishlistSchema.find(query).exec().then(user =>{
                    console.log(user);
                    res.json(user);
                }).catch(error => {
                    console.error(error);
                    res.sendStatus(500);
        })
}

        }
    });
});

//Editing the wish list
router.route('/edit-details:userId').put((req, res, next) => {
    var query = {UserId: req.params.userId};

    wishlistSchema.updateOne(query, {$set:{ProductObject: req.body}}, (error, data) => {
                if (error) {
                    return next(error);
                } else {
                    console.log(data);
                    return res.json(data);
                }
            })

});


module.exports = router;