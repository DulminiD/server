let mongoose = require('mongoose')
var express = require('express')
multer = require('multer')
uuidv4 = require('uuid/v4'),
router = express.Router();


const DIR = './public/';

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, DIR);
    },
    filename: (req, file, cb) => {
        const fileName = file.originalname.toLowerCase().split(' ').join('-');
        cb(null, uuidv4() + '-' + fileName)
    }
});

var upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype == "image/png" || file.mimetype == "image/jpg" || file.mimetype == "image/jpeg") {
            cb(null, true);
        } else {
            cb(null, false);
            return cb(new Error('Only .png, .jpg and .jpeg format allowed!'));
        }
    }
});

let ProductSchema = require('../Model/Products');

//Create Product
router.route('/add-product').post(upload.array('ImageOfProduct',5),(req, res, next) => {
    const url = req.protocol + '://' + req.get('host')
    const product = new ProductSchema({
        _id: new mongoose.Types.ObjectId(),
        ProductName: req.body.ProductName,
        ProductBrand: req.body.ProductBrand,
        Category: req.body.Category,
        PricePerUnit: req.body.PricePerUnit,
        SubCategory: req.body.SubCategory,
    });

    for(var i=0;i<req.files.length;i++) {
        product.Details.push({
            "imgPath": url + '/public/' + req.files[i].filename,
            "color" : req.body.ColorOfImg[i],
            "small" : req.body.StockSmall[i],
            "medium" : req.body.StockMedium[i],
            "large" : req.body.StockLarge[i],
            "xl" : req.body.StockXL[i]

        })
    }

    var datetime = new Date();
    product.AddDate = datetime.toISOString().slice(0,10)

    product.save().then(result => {
        res.status(201).json({
            message: "Product Saved successfully!",
            userCreated: {
                _id: result._id,
                ImageOfProduct: result.ImageOfProduct
            }

        })
    }).catch(err => {
        console.log(err),
            res.status(500).json({
                error: err
            });
    })

});

// READ Products
router.route('/').get((req, res) => {
    ProductSchema.find({}).sort({AddDate:'desc'}).exec((error,data) => {
        if (error) {
            return next(error)
        } else {
            res.json(data)
        }
    })
})

// Get Single Product
router.route('/view-product/:id').get((req, res) => {
    ProductSchema.findById(req.params.id, (error, data) => {
        if (error) {
            return (error)
        } else {
            res.json(data)
        }
    })
})

// Get Products relevant to Category
router.route('/get-products/:category').get((req,res) => {
    var Query = {SubCategory : req.params.category}
    ProductSchema.find(Query, (error,data) => {
        if (error) {
            return next(error)
        } else {
            res.json(data)
        }
    })
})

// search function
router.route('/search/:id').get((req,res) => {
   ProductSchema.find({$text: {$search: req.params.id}}, {score: {$meta: "textScore"}}).sort({score:{$meta:"textScore"}}).exec((error,data) => {
       if (error) {
           return next(error)
       } else {
           res.json(data)
       }
   })

});

//update when purchase
router.route('/sold/:id/:color/:size/:quantity').post(async (req,res) => {

     ProductSchema.findById(req.params.id, (error, data) => {
         const index = data.Details.map(e => e.color).indexOf(req.params.color);
         const currentval = data.Details[index][req.params.size]
         newVal = parseInt(currentval) - parseInt(req.params.quantity)


         var s = "Details.$." + req.params.size;

         ProductSchema.findOneAndUpdate(
             {_id: req.params.id, "Details.color": req.params.color},
             {
                 $set: {
                     [s]: newVal
                 }
             },
             {new: true})
             .then(() => {
                 res.sendStatus(200);
             }).catch(err => {
             console.log("eorrrro")
             console.error(err)
         })
     });
})

//update Products Details
router.route('/editProductsDetails/:id').put((req, res)=> {

    ProductSchema.findOneAndUpdate(
        {_id:req.params.id},
        {
            $set: {
                "ProductName" : req.body.ProductName,
                "ProductBrand" : req.body.ProductBrand,
                "Category" : req.body.Category,
                "SubCategory" : req.body.SubCategory,
                "PricePerUnit" : req.body.PricePerUnit
            }
        },
        {new: true})
        .then(() => {
            res.sendStatus(200);
        }).catch(err => {
        console.log("eorrrro")
        console.error(err)
    });

})

//update a Item of a Product
router.route('/editItemOfProduct/:id').put((req,res) => {
    ProductSchema.findOneAndUpdate(
        {_id:req.params.id , "Details.color":req.body.color},
        {
            $set: {
                "Details.$.small":req.body.small,
                "Details.$.medium":req.body.medium,
                "Details.$.large":req.body.large,
                "Details.$.xl":req.body.xl,
            }
        },{new: true})
        .then(() => {
            res.sendStatus(200);
        }).catch(err => {
        console.log("error")
        console.error(err)
    });

})

//add newItem to currentProduct
router.route('/addnewItemToProduct/:id').post(upload.array('image',5),(req,res) => {
    const url = req.protocol + '://' + req.get('host')
    ProductSchema.findByIdAndUpdate(req.params.id, {
        $push: {
            "Details" : {
                "imgPath" :  url + '/public/' + req.files[0].filename,
                "color" : req.body.color,
                "small" : req.body.small,
                "medium" : req.body.medium,
                "large" : req.body.large,
                "xl" : req.body.xl
            }
        }
    },{safe: true, upsert: true, new : true},
    function(err, model) {
        console.log(err);
    });
});

//delete One item from product
router.route('/deleteOneItemFromProduct/:id/:color').put((req,res) => {
    ProductSchema.findByIdAndUpdate(req.params.id, {
        $pull : {
            "Details" : {color : req.params.color}
        }
    },{safe: true, upsert: true, new : true},).then(() => {
        res.sendStatus(200)
    }).catch(err => {
        console.log(err)
    })
});

module.exports = router;