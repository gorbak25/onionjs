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

//prepare a meek connection
meek = new MeekConnection(meek_server, front_domain, true, true);

meek.ready.then(()=>{
    //create a new meek data stream
    meek_stream = meek.create_new_stream();

    //establish a tor connection
    tls_tor = new TLS_TOR_Connection(meek_stream);

    tls_tor.ready.then(()=>{
        tor = new TOR_Protocol(tls_tor);
        /*Create a link protocol v3 TOR version cell*/
       /* var buf = forge.util.createBuffer()
        buf.putInt16(2) //circID
        buf.putByte(7) //VERSIONS
        buf.putInt16(2)//PAYLOAD LEN
        buf.putInt16(3) //link protocol v3

        tls_tor.set_on_pass_upstream_fun((bytes)=>{});

        tls_tor.send_downstream_fun(buf.getBytes());*/
    });

});
