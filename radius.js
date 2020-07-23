
// Debug level, set between 0 and 3
var debug_level = 3;

// The state value for session persistence
var session_state = "";

// packet type enum object
var pkt_type = Object.freeze({

  ACCESS_REQUEST:        1, 
  ACCESS_ACCEPT:         2,
  ACCESS_REJECT:         3,
  ACCOUNTING_REQUEST:    4,
  ACCOUNTING_RESPONSE:   5,
  ACCESS_CHALLENGE:      11,
  STATUS_SERVER:         12,
  STATUS_CLIENT:         13,
  RESERVED:             255,

  value: {1: "ACCESS_REQUEST", 2: "ACCESS_ACCEPT", 3: "ACCESS_REJECT", 
         4: "ACCOUNTING_REQUEST", 5: "ACCOUNTING_RESPONSE",
         11: "ACCESS_CHALLENGE", 12: "STATUS_SERVER", 13: "STATUS_CLIENT",
         255: "RESERVED"}

});

// Attribute type enum object
var avp_type = Object.freeze({

  USER_NAME:             1,
  USER_PASSWORD:         2,
  CHAP_PASSWORD:         3,
  NAS_IP_ADDRESS:        4,
  NAS_Port:              5,
  STATE:                 24,
  NAS_IDENTIFIER:        32,
  MESSAGE_AUTHENTICATOR: 80,

  value: {1: "USER_NAME", 2: "USER_PASSWORD", 3: "CHAP_PASSWORD",
         4: "NAS_IP_ADDRESS", 5: "NAS_Port", 
         24: "STATE", 32: "NAS_IDENTIFIER", 80: "MESSAGE_AUTHENTICATOR"},

  format: {1: "TEXT", 2: "STRING", 3: "STRING",
          4: "IPV4ADDR", 5: "INTEGER", 
          24: "STRING", 32: "STRING", 80: "STRING" }

});

// debug function, set debug_level above
function debug(s, level, message) {
  if ( debug_level >= level ) {
    s.log( message );
  }
}

// Convert two bytes in a packet to a 16bit int
function to_int(A, B) {
  return (((A & 0xFF) << 8) | (B & 0xFF));
}

// Convert four bytes in a packet to a 32bit int
function to_int32(A, B, C, D) {
  return ( ((A & 0xFF) << 24) | ((B & 0xFF) << 16) | ((C & 0xFF) << 8) | (D & 0xFF) );
}

// Encode the given number to two bytes (16 bit)
function to_bytes( number ) {
  return String.fromCodePoint( ((number>>8) & 0xff), (number & 0xff) ).toBytes();
}

// Encode the given number to 4 bytes (32 bit)
function to_bytes32( number ) {
  return String.fromCodePoint( (number>>24)&0xff, (number>>16)&0xff, (number>>8)&0xff, number&0xff ).toBytes();
}

// Update the length field to match the size of the packet
function update_length(data) {
  return data.slice(0,2) + to_bytes(data.length) + data.slice(4);
}

// Add an additional AV Pair to the packet
function add_attribute(data, attr, value) {
  var len;
  switch(avp_type.format[attr]) {
    case "TEXT":
    case "STRING":
      len = 2 + value.length; // Length includes type and length
      data += String.fromCharCode(attr) + String.fromCharCode(len) + value;
      break;
  }
  return data;
}

// Search for and retrieve attributes matching the search
function get_attribute_values(s, data, search) {
  var length = data.length;
  var index = 20;
  var results = [];
  while (index < data.length ) {
    var type = data.codePointAt(index);
    var length = data.codePointAt(index+1);
    debug(s, 3, "get_attribute_value: checking: " + ( avp_type.value[type] || type.toString() ) + ", length: " + length);
    if ( type == search ) {
      var result = data.slice(index+2, index+length)
      results.push( result );
      debug(s, 2, "get_attribute_value: result: " + result.toString('hex') );
    }
    index += length
  }
  return results;
}

// Update the Message-Authenticator attribute (if we modified something)
function update_msg_auth(s, data) {
  var length = data.length;
  var index = 20;
  while (index < data.length ) {
    var type = data.codePointAt(index);
    var length = data.codePointAt(index+1);
    debug(s, 3, "update_msg_auth: checking: " + ( avp_type.value[type] || type.toString() ) + ", length: " + length);
    if ( type == avp_type.MESSAGE_AUTHENTICATOR ) {
      debug(s, 1, "update_msg_auth: Updating Message-Authentication." );
      data = data.slice(0,index+2) + Array(16).fill( String.fromCodePoint(0x00) ).join('') + data.slice(index+length);
      debug(s, 3, "update_msg_auth: Regenerating Message-Authentication with: " + data.toString('hex') );
      var cr = require('crypto');
      var hmac = cr.createHmac('md5', s.variables.radius_secret);
      hmac.update(data)
      var digest = hmac.digest();
      debug(s, 2, "update_msg_auth: Updated Message-Authentication: " + digest.toString('hex') );
      data = data.slice(0,index+2) + digest + data.slice(index+length);
    }
    index += length
  }
  return data;
}

// The main parser function
function radius_parser(s) {

  s.on("upload", function(data,flags) {
    var code, identifier, length, authenticator, attributes;
    code = data.codePointAt(0);
    identifier = data.codePointAt(1);
    length = to_int( data.codePointAt(2), data.codePointAt(3) );
    authenticator = data.slice(4, 19);
    attributes = data.slice(20);
    debug(s, 1, "radius_parser: Incoming Request Packet: Type: " + pkt_type.value[code] );
    debug(s, 2, "radius_parser: In Req Dump: " + data.toString('hex') );

    // Access Request - if client provided state, use for persistence
    if ( code == pkt_type.ACCESS_REQUEST ) {
      var state = get_attribute_values(s, data, avp_type.STATE);
      if ( state.length == 1 ) {
        session_state = state[0];
      }
    } 

    // Add Attributes here
    data = add_attribute(data, avp_type.NAS_IDENTIFIER, "NGINX Plus");

    // Update the packet length (needed if packet is modified)
    data = update_length(data)

    // Update the message authenticator (needed if packet is modified)
    data = update_msg_auth(s, data);

    debug(s, 2, "radius_parser: Out Req Dump: " + data.toString('hex') );
    s.send(data);
  });

  s.on("download", function(data, flags) {
    var code, identifier, length, authenticator, attributes;
    code = data.codePointAt(0);
    identifier = data.codePointAt(1);
    length = to_int( data.codePointAt(2), data.codePointAt(3) );
    authenticator = data.slice(4, 19);
    attributes = data.slice(20);
    debug(s, 1, "radius_parser: Incoming Response Packet: Type: " + pkt_type.value[code] );
    debug(s, 2, "radius_parser: In Res Packet: " + data.toString('hex') );

    // Access Challenge - Use State for persistence
    if ( code == pkt_type.ACCESS_CHALLENGE ) {
      var state = get_attribute_values(s, data, avp_type.STATE);
      if ( state.length == 1 ) {
        session_state = state[0];
        var server = s.variables.upstream_addr.split(',').pop().split(':')[0].trim();
        s.variables.persistence = server;
      }
    } 

    debug(s, 2, "radius_parser: Out Res Packet: " + data.toString('hex') );
    s.send(data);
  });

}

// Return the session_state to NGINX
function get_state(s) {
  return session_state;
}

export default {radius_parser, get_state};

