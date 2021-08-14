const express = require('express')
const { ApolloServer } = require('apollo-server-express')
const MongoClient = require('mongodb').MongoClient
const typeDefs = require('./schema/schema.graphql')
const { GraphQLDateTime, GraphQLDate, GraphQLTime } = require('graphql-iso-date')
const mongodb = require("mongodb")
const Long = mongodb.Long

const url = 'mongodb://localhost:27017'
const client = new MongoClient(url, {useNewUrlParser: true, useUnifiedTopology: true})
client.connect(function (err){
  console.log('MongoDB connected')
  db = client.db('sensor')
})

const app = express()

const resolvers = {

  ISODateTime: GraphQLDateTime,
  ISODate: GraphQLDate,
  ISOTime: GraphQLTime,

  Query: {
    classifications: async () => { //klasifikasi serangan pada protokol Samba
        return Classification = await db.collection('dionaeaembedded')
        .aggregate([
          {
              $match: {
                  local_port: 445
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
                      connection_protocol: "$connection_protocol",
                      remote_host:"$remote_host",
                      connection_timestamp: "$connection_timestamp", 
                      offer_url:"$offer.offer_url", 
                  }
              }
          },
          {
              $project: {
                  local_port:"$_id.local_port",
                  connection_protocol: "$_id.connection_protocol",
                  remote_host:"$_id.remote_host",
                  connection_timestamp: "$_id.connection_timestamp",
                  offer_url:"$_id.offer_url",  
                  classification : {
                      $cond : {
                          if : { 
                              $regexMatch: {input: "$_id.offer_url", regex: /^smb/, options: "i" }
                          },
                          then : "Session Hijacking",
                          else : {
                              $cond : {
                                  if : { 
                                      $regexMatch: {input: "$_id.offer_url", regex: /^http/, options: "i" }
                                  },
                                  then : "Link Manipulation",
                                  else : "Undefined"
                              }
                          }
                      }
                  }
              }
          },
          {
              $limit : 10000
          }
        ], {allowDiskUse:true}).toArray()
    },

    smburls: async () => { //menampilkan data offer_url yang memiliki data url "smb"
        return SMBUrl = await db.collection('dionaeaembedded')
        .aggregate([
          {
              $match: {
                  local_port: Long.fromString("445"), 
                  "offer.offer_url": {$regex:/^smb/}
              }
          },
          {
              $group: {
                  _id: {
                      offer_url:"$offer.offer_url",
                      connection_timestamp:{
                        $toDate: { 
                            $multiply:["$connection_timestamp", 1000 ] }}
                  }
              }
          },
          {
              $project: {
                  offer_url: "$_id.offer_url",
                  connection_timestamp: "$_id.connection_timestamp",
                  _id: 0
              }
          },
          {
              $sort:{
                  connection_timestamp: 1
              }
          }
       ]).toArray()
    },

    top_smburl: async () => { //menampilkan top 10 data offer_url yang memiliki data url "smb"
        return TopSMBUrl = await db.collection('dionaeaembedded')
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
                        offer_url:"$offer.offer_url",
                        connection_timestamp:{
                            $toDate: { 
                                $multiply:["$connection_timestamp", 1000 ] }}
                        },
                    count: { 
                        $sum: 1}
                }
            },
            {
                $project: {
                    offer_url:"$_id.offer_url",
                    connection_timestamp:"$_id.connection_timestamp",
                    count: "$count"
                }
            },
            {
                $sort: {
                    count: -1
                }
            },
            {
                $limit: 10
            }
          ]).toArray()
    },

    connections: async () => { //menampilkan konversi timestamp dan mengurutkannya berdasarkan perhitungan jumlah serangan yang terjadi
      return Connection = await db.collection('dionaeaembedded')
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
                    connection_timestamp:{
                        $toDate: { 
                            $multiply:["$connection_timestamp", 1000 ] }}
                    },
                count: { 
                    $sum: 1}
            }
        },
        {
            $project: {
                count: "$count",
                connection_timestamp: {$dateToString: { format: "%Y-%m-%d", date: "$_id.connection_timestamp" }}
            }
        },
        {
            $sort: {
                connection_timestamp: 1
            }
        }
      ]).toArray()
    },
    
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
    
    malwares: async () => { //menampilkan urutan data top 10 malware
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
    }
  }
}

const server = new ApolloServer({
  typeDefs,
  resolvers
})

server.applyMiddleware({ app, path: '/graphql'})
app.listen(5000, () => console.log(`Server ready at http://localhost:5000/graphql`))
