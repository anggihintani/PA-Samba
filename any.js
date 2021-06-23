// Requires official Node.js MongoDB Driver 3.0.0+
const mongodb = require("mongodb");
const Long = mongodb.Long;

const client = mongodb.MongoClient;
const url = "mongodb://localhost:27017/sensor";

//const geoip = require('geoip-country')

client.connect(url, function (err, client) {
    
    const db = client.db("sensor");
    const collection = db.collection("dionaeaembedded2");
    
    const options = {
        allowDiskUse: true
    };
    
    const pipeline = [
        {$match: {local_port: 3306}},
     {
       $project:
         {
          count: "$count",
          connection_timestamp: { 
            $toDate: { 
                $multiply:["$connection_timestamp", 1000 ] }}
         }
     },
     {
    $group: {
        _id: {
            $dateToString: {
                format: "%Y-%m-%d - %H-%M-%S", 
                date: "$connection_timestamp"}},
                count: {
                    $sum: 1}
                }},
    {$sort:{_id:-1}},
    {$limit:10000}
    ];
    
    const cursor = collection.aggregate(pipeline, options);
    
    cursor.forEach(
        function(doc) {
            console.log(doc);
        }, 
        function(err) {
            client.close();
        }
    );
    
    // Created with Studio 3T, the IDE for MongoDB - https://studio3t.com/
    
});
