const mongoose = require('mongoose');
const Schema = mongoose.Schema;

let productSchema = new Schema({
    _id: mongoose.Schema.Types.ObjectId,
    ProductName: {
        type: String
    },
    ProductBrand: {
      type:String
    },
    Category: {
        type: String
    },
    PricePerUnit: {
        type: Number
    },
    SubCategory: {
        type: String
    },

    AddDate: {
        type:String,
    },
    Details:[],
}, {
    collection: 'products'
    });
productSchema.index({'$**': 'text'});


module.exports = mongoose.model('Product', productSchema);
