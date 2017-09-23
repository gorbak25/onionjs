console.log("ONION JS Started");
var front_domain = "https://a0.awsstatic.com/";
var meek_server = "d2zfqthxsdq309.cloudfront.net";
//var front_domain = meek_server

//a function to create a random token
//not to be used for cryptographic purposes
function makeRewritorToken(len) {
    var text = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    for (var i = 0; i < len; i++)
        text += possible.charAt(Math.floor(Math.random() * possible.length));

    return text;
}

//random tokens
var head = makeRewritorToken(10);
var head_val = makeRewritorToken(10);

//creates a sessionId
function makeSessionId()
{
    return btoa("OnionJS"+forge.random.getBytesSync(40)).substring(1,40);
}

//function to read response data from an XML HTTP request
function readResponseBody(xhr) {
    var data;
    if (!xhr.responseType || xhr.responseType === "text") {
        data = xhr.responseText;
    } else if (xhr.responseType === "document") {
        data = xhr.responseXML;
    } else {
        data = xhr.response;
    }
    return data;
}

//determine whether the domain fronting setup is correct
function pingMeekServer()
{
    return new Promise(function(resolve, reject){
        var xhr = new XMLHttpRequest();
        xhr.onload = function() {
            msg = readResponseBody(xhr);
            if(msg === "I’m just a happy little web server.\n") {
                console.log("Meek server responded successfully");
                resolve();
            }
            else {
                console.log("Check your fronting configuration");
                reject();
            }
        };
        xhr.onerror = function() {
          reject();
        };
        xhr.open('GET', front_domain, true);
        xhr.setRequestHeader(head, head_val);
        xhr.send(null);
    });
}

function base64ArrayBuffer(arrayBuffer) {
    var base64    = ''
    var encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    var bytes         = new Uint8Array(arrayBuffer)
    var byteLength    = bytes.byteLength
    var byteRemainder = byteLength % 3
    var mainLength    = byteLength - byteRemainder

    var a, b, c, d
    var chunk

    // Main loop deals with bytes in chunks of 3
    for (var i = 0; i < mainLength; i = i + 3) {
        // Combine the three bytes into a single integer
        chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]

        // Use bitmasks to extract 6-bit segments from the triplet
        a = (chunk & 16515072) >> 18 // 16515072 = (2^6 - 1) << 18
        b = (chunk & 258048)   >> 12 // 258048   = (2^6 - 1) << 12
        c = (chunk & 4032)     >>  6 // 4032     = (2^6 - 1) << 6
        d = chunk & 63               // 63       = 2^6 - 1

        // Convert the raw binary segments to the appropriate ASCII encoding
        base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d]
    }

    // Deal with the remaining bytes and padding
    if (byteRemainder == 1) {
        chunk = bytes[mainLength]

        a = (chunk & 252) >> 2 // 252 = (2^6 - 1) << 2

        // Set the 4 least significant bits to zero
        b = (chunk & 3)   << 4 // 3   = 2^2 - 1

        base64 += encodings[a] + encodings[b] + '=='
    } else if (byteRemainder == 2) {
        chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1]

        a = (chunk & 64512) >> 10 // 64512 = (2^6 - 1) << 10
        b = (chunk & 1008)  >>  4 // 1008  = (2^6 - 1) << 4

        // Set the 2 least significant bits to zero
        c = (chunk & 15)    <<  2 // 15    = 2^4 - 1

        base64 += encodings[a] + encodings[b] + encodings[c] + '='
    }

    return base64
}

//sends data to the meek server and returns the response
function sendFrontedData(session, payload)
{
    return new Promise(function(resolve, reject){
        var xhr = new XMLHttpRequest();
        xhr.onload = function() {
            msg = readResponseBody(xhr);
            console.log(msg);
            console.log("Status:", xhr.status, xhr.statusText);

            console.log("RECEIVED: ", base64ArrayBuffer(msg));

            resolve(atob(base64ArrayBuffer(msg))); //Dirty hack
        };
        xhr.onerror = function() {
            console.log("Error", xhr.status, xhr.statusText);
            reject();
        };
        xhr.open('POST', front_domain, true);
        xhr.responseType = "arraybuffer";
        xhr.setRequestHeader(head, head_val);
        xhr.setRequestHeader("X-Session-Id", session);
        xhr.overrideMimeType("application/octet-stream");
        xhr.setRequestHeader("Content-Type", "application/octet-stream")

        function str2ab(str) {
          var buf = new ArrayBuffer(str.length); // 2 bytes for each char
          var bufView = new Uint8Array(buf);
          for (var i=0, strLen=str.length; i<strLen; i++) {
            bufView[i] = str.charCodeAt(i);
          }
          return buf;
        }

        console.log(str2ab(payload))

        xhr.send(str2ab(payload));
    });
}

function rewriteUserAgentHeader(e) {
    console.log("INTERCEPTOR");
    var good = false;
    for (var header of e.requestHeaders) {
        if (header.name == head && header.value == head_val) {
            good = true;
        }
    }
    if(!good) return;
    var new_headers = []
    for (var header of e.requestHeaders) {
        if (header.name.toLowerCase() == "host") {
            header.value = meek_server;
            new_headers.push(header)
        }
        if(header.name == "X-Session-Id")
        {
        new_headers.push(header)
        }
        if(header.name == "Content-Type")
        {
        new_headers.push(header)
        }
        if(header.name == "Content-Length")
        {
        new_headers.push(header)
        }
    }

    return {requestHeaders: new_headers};
}

browser.webRequest.onBeforeSendHeaders.addListener(
    rewriteUserAgentHeader,
    {urls: [front_domain], types: ["xmlhttprequest"]},
    ["blocking", "requestHeaders"]
);

//return CipherSuites suitable for a TOR handshake
function getTorInitialClientCipherSuites(){
    console.log(forge.tls.CipherSuites)
    return [
    forge.tls.CipherSuites.TLS1_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    forge.tls.CipherSuites.TLS1_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    forge.tls.CipherSuites.TLS1_DHE_RSA_WITH_AES_256_SHA,
    forge.tls.CipherSuites.TLS1_DHE_DSS_WITH_AES_256_SHA,
    forge.tls.CipherSuites.TLS1_ECDH_RSA_WITH_AES_256_CBC_SHA,
    forge.tls.CipherSuites.TLS1_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
    forge.tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA,
    forge.tls.CipherSuites.TLS1_ECDHE_ECDSA_WITH_RC4_128_SHA,
    forge.tls.CipherSuites.TLS1_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    forge.tls.CipherSuites.TLS1_ECDHE_RSA_WITH_RC4_128_SHA,
    forge.tls.CipherSuites.TLS1_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    forge.tls.CipherSuites.TLS1_DHE_RSA_WITH_AES_128_SHA,
    forge.tls.CipherSuites.TLS1_DHE_DSS_WITH_AES_128_SHA,
    forge.tls.CipherSuites.TLS1_ECDH_RSA_WITH_RC4_128_SHA,
    forge.tls.CipherSuites.TLS1_ECDH_RSA_WITH_AES_128_CBC_SHA,
    forge.tls.CipherSuites.TLS1_ECDH_ECDSA_WITH_RC4_128_SHA,
    forge.tls.CipherSuites.TLS1_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
    forge.tls.CipherSuites.SSL3_RSA_RC4_128_MD5,
    forge.tls.CipherSuites.SSL3_RSA_RC4_128_SHA,
    forge.tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA,
    forge.tls.CipherSuites.TLS1_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
    forge.tls.CipherSuites.TLS1_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
    forge.tls.CipherSuites.SSL3_EDH_RSA_DES_192_CBC3_SHA,
    forge.tls.CipherSuites.SSL3_EDH_DSS_DES_192_CBC3_SHA,
    forge.tls.CipherSuites.TLS1_ECDH_RSA_WITH_DES_192_CBC3_SHA,
    forge.tls.CipherSuites.TLS1_ECDH_ECDSA_WITH_DES_192_CBC3_SHA,
    forge.tls.CipherSuites.SSL3_RSA_FIPS_WITH_3DES_EDE_CBC_SHA,
    forge.tls.CipherSuites.SSL3_RSA_DES_192_CBC3_SHA];
}

setTimeout(function () {
   // pingMeekServer().then(()=>{
        console.log("Meek is ready");
        const session = makeSessionId();
        //sendFrontedData(session, makeRewritorToken(516));


        randomSNI = "www."+makeRewritorToken(21).toLowerCase()+".com"
        // create TLS client
        var client = forge.tls.createConnection({
            server: false,
            //version: forge.tls.Versions.TLS_1_0,
            caStore: []/* Array of PEM-formatted certs or a CA store object */,
            sessionCache: {},
            // supported cipher suites in order of preference
            cipherSuites: getTorInitialClientCipherSuites(),
            virtualHost: randomSNI,
            verify: function(connection, verified, depth, certs) {

                this.caStore.addCertificate(forge.pki.certificateToPem(certs[0]))
                this.caStore.addCertificate(forge.pki.certificateToPem(certs[0]))
                this.caStore.addCertificate(forge.pki.certificateToPem(certs[0]))

                console.log(certs[0].isIssuer(certs[0]))

                console.log("WTF")
                console.log(certs)
                return true;
                if(depth === 0) {
                    var cn = certs[0].subject.getField('CN').value;
                    console.log(cn)
                    console.log(randomSNI)
                    console.log(certs)
                    if(cn !== 'example.com') {
                        verified = {
                            alert: forge.tls.Alert.Description.bad_certificate,
                            message: 'Certificate common name does not match hostname.'
                        };
                    }
                }
                return verified;
            },
            connected: function(connection) {
                console.log('connected');
                // send message to server
                connection.prepare(forge.util.encodeUtf8('Hi server!'));
                /* NOTE: experimental, start heartbeat retransmission timer
                myHeartbeatTimer = setInterval(function() {
                  connection.prepareHeartbeatRequest(forge.util.createBuffer('1234'));
                }, 5*60*1000);*/
            },
            /* provide a client-side cert if you want
            getCertificate: function(connection, hint) {
              return myClientCertificate;
            },
            /* the private key for the client-side cert if provided */
            getPrivateKey: function(connection, cert) {
                //return myClientPrivateKey;
            },
            tlsDataReady: function(connection) {
                // TLS data (encrypted) is ready to be sent to the server
                var to_send = connection.tlsData.getBytes()

                console.log("Sending: ", btoa(to_send));
                console.log("TO_SEND LEN: ", to_send.length)
                console.log(to_send)
                sendFrontedData(session, to_send).then(
                    (data)=>{
                        console.log("Processing: ", base64ArrayBuffer(data));
                        this.process(data);

                    }
                );

            },
            dataReady: function(connection) {
                // clear data from the server is ready
                console.log('the server sent: ' +
                    forge.util.decodeUtf8(connection.data.getBytes()));
                // close connection
                connection.close();
            },
            /* NOTE: experimental
            heartbeatReceived: function(connection, payload) {
              // restart retransmission timer, look at payload
              clearInterval(myHeartbeatTimer);
              myHeartbeatTimer = setInterval(function() {
                connection.prepareHeartbeatRequest(forge.util.createBuffer('1234'));
              }, 5*60*1000);
              payload.getBytes();
            },*/
            closed: function(connection) {
                console.log('disconnected');
            },
            error: function(connection, error) {
                console.log('uh oh', error);
            }
        });

// start the handshake process
        client.handshake();

// when encrypted TLS data is received from the server, process it
        //client.process(encryptedBytesFromServer);





    //});
}, 1000);




