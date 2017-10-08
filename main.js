/*
Onion JS
Full native Javascript TOR implementation by using ONLY XHR calls :D
Currently it works as a browser extension to not care about COR policy
It can be run natively within a browser by setting up a meek server with CORS headers XD
TLS is provided by the forge library. You need to use my fork of this library as I needed
to implement some things to be able to connect to an onion router -> for specifics see forge/lib/tls.js and forge/lib/aesCipherSuites.js
Grzegorz Uriasz <gorbak25@gmail.com>
*/

var meek_server = "d2zfqthxsdq309.cloudfront.net";

var as_browser_extension = true;
var front_domain = "https://a0.awsstatic.com/"; //only used when as_browser_extension is true - otherwise we can not gain access to the HOST header

console.log("ONION JS Started");
/*
// Create and initialize EC context
// (better do it once and reuse it)
var ec = new elliptic.ec('secp256k1');

// Generate keys
var key = ec.genKeyPair();

// Sign the message's hash (input must be an array, or a hex-string)
var msgHash = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ];
var signature = key.sign(msgHash);

// Export DER encoded signature in Array
var derSign = signature.toDER();

function toHexString(byteArray) {
    return Array.from(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}



// Verify signature
console.log(toHexString(derSign))
console.log(key.verify(msgHash, derSign));

// CHECK WITH NO PRIVATE KEY

var pubPoint = key.getPublic();
var x = pubPoint.getX();
var y = pubPoint.getY();

// Public Key MUST be either:
// 1) '04' + hex string of x + hex string of y; or
// 2) object with two hex string properties (x and y); or
// 3) object with two buffer properties (x and y)
var pub = pubPoint.encode('hex');                                 // case 1
var pub = { x: x.toString('hex'), y: y.toString('hex') };         // case 2
//var pub = { x: x.toBuffer(), y: y.toBuffer() };                   // case 3
//var pub = { x: x.toArrayLike(elliptic.Buffer), y: y.toArrayLike(elliptic.Buffer) }; // case 3

// Import public key
var key = ec.keyFromPublic(pub, 'hex');

// Signature MUST be either:
// 1) DER-encoded signature as hex-string; or
// 2) DER-encoded signature as buffer; or
// 3) object with two hex-string properties (r and s); or
// 4) object with two buffer properties (r and s)

var signature = toHexString(derSign)//'304402200c11592e6268e6a9bfa8a80e96cd21c0a2cbb015f2898a2a5b40857d146cc08902207100819c612082a85ef7fbb661f9955408a83c58cd6b85fc4c81fe5a9a7e0af2'; // case 1
//var signature = new Buffer('...'); // case 2
//var signature = { r: 'b1fc...', s: '9c42...' }; // case 3

// Verify signature
console.log(key.verify(msgHash, signature));

*/

//prepare a meek connection
meek = new MeekConnection(meek_server, front_domain, true, true);

meek.ready.then(()=>{
    //create a new meek data stream
    meek_stream = meek.create_new_stream();

    //establish a tor connection
    tls_tor = new TLS_TOR_Connection(meek_stream);

    tls_tor.ready.then(()=>{
        //establish the onion router identity and prepare the channel for circuits
        tor = new TOR_Protocol(tls_tor);

        tor.ready.then(()=>{
            var circuit = tor.create_new_circuit();
            circuit.ready.then(()=>{
                console.log(circuit);
                console.log("ONION IS READY :P");
            });
        });
    });

});
