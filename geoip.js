const geoip = require('geoip-country')

const ip = "91.211.21.217"
const geo = geoip.lookup(ip)
console.log(geo)