const express = require('express')
const { ApolloServer } = require('apollo-server-express')
const MongoClient = require('mongodb').MongoClient
const typeDefs = require('./schema/schema.graphql')
const { GraphQLDateTime } = require('graphql-iso-date')
const mongodb = require("mongodb")
const Long = mongodb.Long
const GraphQLJSON = require('graphql-type-json')

const url = 'mongodb://localhost:27017'
const client = new MongoClient(url, {useNewUrlParser: true, useUnifiedTopology: true})
client.connect(function (err){
  console.log('MongoDB connected')
  db = client.db('sensor')
})

const app = express()

const resolvers = {

  ISODateTime: GraphQLDateTime,
  JSON: GraphQLJSON,

  Query: {
    sambas: async () => { //mengambil semua data port 445 dari basis data
      return Samba = await db.collection('dionaeaembedded')
      .find({local_port:445}).limit(10).toArray()
      .then(res => {
          return res
      })
    },

    /*connection_timestamp: async () => { //menampilkan konversi timestamp dan mengurutkannya berdasarkan perhitungan jumlah serangan yang terjadi
      return Connection = await db.collection('dionaeaembedded')
      .aggregate([
        {
          $match: {
              local_port: Long.fromString("445")
          }
        },
        {
           $group: {
                _id: {
                    connection_timestamp:"$connection_timestamp"
                },
                count: {
                    $sum : 1
                }
            }
        },
        {
            $project: {
                count: "$count",
                connection_timestamp: "$_id.connection_timestamp",
                _id: 0
            }
        },
        {
          $sort: {
            connection_timestamp: -1}
        },
        {
          $limit : 10
        }
      ],
      {allowDiskUse: true}).toArray()
    },*/
    
    remote_host: async () => { //menampilkan urutan data top 10 IP
      return RemoteHost = await db.collection('dionaeaembedded')
      .aggregate([
        {
            $match: {
                local_port: Long.fromString("445")
            }
        },
        {
          $group: {
            _id: { 
                remote_host: "$remote_host",
                local_port: "$local_port"
              },
            count: {
                  $sum : 1
              }
            }
        },
        {
          $project: {
              count: "$count",
              remote_host: "$_id.remote_host",
              local_port: "$_id.local_port",
              _id: 0
            }
        },
        {
            $sort: {
                count: -1
            }
        },
        {
            $limit : 10
        }
      ]).toArray()
    },

    malwares: async () => { //menampilkan urutan data top 10 malware yang telah diunduh oleh Dionaea
      return Malware = await db.collection('dionaeaembedded')
      .aggregate([
        {
            $match: {
                local_port: Long.fromString("445")
            }
        },
        {
            $unwind: "$download"
        },
        {
            $unwind: "$download.download_md5_hash"
        },
        {
            $group: {
                _id: {
                    local_port:"$local_port", 
                    download_md5_hash:"$download.download_md5_hash"
                },
                count: {
                    $sum : 1
                }
            }
        },
        {
            $project: {
                count: "$count",            
                local_port: "$_id.local_port",
                download_md5_hash: "$_id.download_md5_hash",
                _id: 0
            }
        },
        {
            $sort:{
                count:-1
            }
        },
        {
            $limit:10
        }
      ]).toArray()
    },

    smburls: async () => { //menampilkan data offer_url yang memiliki url berisi "smb"
      return SMBUrl = await db.collection('dionaeaembedded')
      .aggregate([
        {
            $match: {
                local_port: Long.fromString("445"), 
                "offer.offer_url": {$regex:/^smb/}
            }
        },
        {
            $unwind: "$offer"
        },
        {
            $unwind: "$offer.offer_url"
        },
        {
            $group: {
                _id: {
                    local_port:"$local_port", 
                    remote_host:"$remote_host",
                    offer_url:"$offer.offer_url"
                },
                count: {
                    $sum : 1
                }
            }
        },
        {
            $project: {
                count: "$count",            
                local_port: "$_id.local_port",
                remote_host:"$_id.remote_host",
                offer_url: "$_id.offer_url",
                _id: 0
            }
        },
        {
            $sort:{
                count:-1
            }
        }
      ]).toArray()
    },

    classification: async () => { //
      return Classification = await db.collection('dionaeaembedded')
      .aggregate([
        {$match: {local_port: 445}},
        {$unwind: "$offer"},
        {$unwind: "$offer.offer_url"},
        {$group: {_id: {local_port:"$local_port", offer_url:"$offer.offer_url", remote_host:"remote_host"}}},
        {$project:{
            local_port:"$_id.local_port", 
            offer_url:"$_id.offer_url", 
            remote_host:"remote_host", 
            classification : {
                $cond : {
                    if : { $regexMatch: {input: "$_id.offer_url", regex: /^smb/, options: "i" }},
                    then : "Phishing Style Attack",
                    else : "Undefined"
                    }
                }}}
        ]).toArray()
    }
  }
}

const server = new ApolloServer({
  typeDefs,
  resolvers
})

server.applyMiddleware({ app, path: '/graphql'})
app.listen(5000, () => console.log(`Server ready at http://localhost:5000/graphql`))
