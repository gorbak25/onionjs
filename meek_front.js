/*
Communicate with a meek server
It handles fragmentation and data pooling from a meek server
it exposes a callback to return data to higher layers in the data processing stream
Incoming data buffering will be handled by forge's tls engine
 */
var PACKET_MAX_SIZE = 10000;
var initial_fetch_delay = 100;
var maximum_pooling_delay = 5000;
var verbose_transmission = false;

//a function to create a random token in browser extension mode
//not to be used for cryptographic purposes
function makeRandomString(len) {
    var text = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    for (var i = 0; i < len; i++)
        text += possible.charAt(Math.floor(Math.random() * possible.length));

    return text;
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

//creates a sessionId
function makeSessionId()
{
    return btoa("OnionJS"+forge.random.getBytesSync(40));
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

function str2ab(str) {
    var buf = new ArrayBuffer(str.length); // 1 bytes for each char
    var bufView = new Uint8Array(buf);
    for (var i=0, strLen=str.length; i<strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

//represents a meek connection
function MeekConnection(meek_server, front_domain, as_browser_extension, ping_the_server)
{
    console.log("Connecting to: ", meek_server);

    this.server = meek_server;
    this.front = front_domain;
    this.as_browser_extension = as_browser_extension;

    //in browser extension mode we are able to fully implement the meek plugable transport protocol

    if(as_browser_extension)
    {
        //random tokens
        this.head_name = makeRandomString(10);
        this.head_val = makeRandomString(10);

        function rewriteReqHeader(e, meek_connection) {
            var good = false;
            for (var header of e.requestHeaders) {
                if (header.name == meek_connection.head_name && header.value == meek_connection.head_val) {
                    good = true;
                }
            }
            if(!good) return;
            console.log("TEST");
            var new_headers = [];
            for (var header of e.requestHeaders) {
                if (header.name.toLowerCase() == "host") {
                    header.value = meek_connection.server;
                    new_headers.push(header);
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

            console.log(new_headers);
            return {requestHeaders: new_headers};
        }

        browser.webRequest.onBeforeSendHeaders.addListener(
            (headers)=>{return rewriteReqHeader(headers, this)},
            {urls: [this.front], types: ["xmlhttprequest"]},
            ["blocking", "requestHeaders"]
        );
    }

    var meek = this;
    this.ready = new Promise(function (resolve, reject) {
        setTimeout(() => {
            if (ping_the_server) {
                meek.ping_server().then(
                    () => {
                        console.log("Meek pinged successfully");
                        resolve();
                    },
                    () => {
                        console.log("Meek ping failed check your fronting configuration");
                        reject();
                    });
            }
            else {
                resolve();
            }
        },(meek.as_browser_extension?2000:0)); //in extension mode 1s for header rewriting initialization
    });
}

//pings the meek server
MeekConnection.prototype.ping_server = function(){
    var meek = this;
    return new Promise(function(resolve, reject){
        var xhr = new XMLHttpRequest();
        xhr.onload = function() {
            msg = readResponseBody(xhr);
            console.log(msg);
            if(msg === "I’m just a happy little web server.\n") {
                resolve();
            }
            else {
                reject();
            }
        };
        xhr.onerror = function() {
            reject();
        };
        xhr.open('GET', meek.as_browser_extension?meek.front:meek.server, true);
        if(meek.as_browser_extension) {
            xhr.setRequestHeader(meek.head_name, meek.head_val);
        }
        xhr.send(null);
    });
};

//creates a new meek data stream
//on_bytes_ready will be called with the received bytes object
MeekConnection.prototype.create_new_stream = function(on_bytes_ready) {
    return new MeekStream(this, on_bytes_ready);
};

//represents a meek data stream within a meek connection
//on_bytes_ready will be called when we receive payload from the meek server
//meek_connection is an instance of MeekConnection
function MeekStream(meek_connection, on_bytes_ready){
    this.outgoing_buffer = forge.util.createBuffer(); //outgoing buffer
    this.session_id = makeSessionId();
    this.on_bytes_ready = on_bytes_ready;
    this.meek_connection = meek_connection;
}

//destroys an open meek stream
MeekStream.prototype.destroy = function(){
    this.outgoing_buffer.clear();
    this.session_id = makeSessionId();
    if(this.fetcher !== undefined)
    {
        clearTimeout(this.fetcher);
        this.fetcher = undefined;
    }
};

//sends and receives data from a meek server
//payload can be an empty string
MeekStream.prototype.round_trip = function(payload){
    var meek = this;
    return new Promise(function(resolve, reject){
        var xhr = new XMLHttpRequest();
        xhr.onload = function() {
            msg = readResponseBody(xhr);
            if(verbose_transmission) {
                console.log("RECEIVED RAW: ", base64ArrayBuffer(msg));
            }
            resolve(atob(base64ArrayBuffer(msg))); //Dirty hack
        };
        xhr.onerror = function() {
            console.log("Error", xhr.status, xhr.statusText);
            reject();
        };
        xhr.open('POST', meek.meek_connection.as_browser_extension?meek.meek_connection.front:meek.meek_connection.server, true);
        xhr.responseType = "arraybuffer";
        if(meek.meek_connection.as_browser_extension) {
            xhr.setRequestHeader(meek.meek_connection.head_name, meek.meek_connection.head_val);
        }
        xhr.setRequestHeader("X-Session-Id", meek.session_id);
        xhr.overrideMimeType("application/octet-stream");
        xhr.setRequestHeader("Content-Type", "application/octet-stream");

        if(verbose_transmission) {
            console.log("SENDING RAW: ", btoa(payload));
        }
        xhr.send(str2ab(payload));
    });
};

//sends bytes to a meek server
MeekStream.prototype.send_bytes = function(payload){
    this.stop_periodical_fetcher();

    this.outgoing_buffer.putBytes(payload);
    this.outgoing_buffer.compact();

    while(this.outgoing_buffer.length() > 0)
    {
        this.round_trip(this.outgoing_buffer.getBytes(PACKET_MAX_SIZE)).then(
            (received)=>{
                this.outgoing_buffer.compact();

                if(received.length > 0) {
                    //data was received so pass it to higher processing layers
                    this.on_bytes_ready(received);
                }
            },
            ()=>{
                console.log("Transmission failed");
                this.destroy();
            }
        );
    }

    this.start_periodical_fetcher();
};

//this function will fetch data from the meek server periodically via specification
//if no data was fetched the fetch interval increases
MeekStream.prototype.fetch_bytes = function(){
    this.round_trip("").then(
        (received)=>{
            if(received.length > 0){
                //data was received so pass it to higher processing layers
                this.on_bytes_ready(received);

                //restart the fetcher
                this.fetcher = undefined;
                this.start_periodical_fetcher();
            }
            else{
                //no data was received so try again
                this.increase_fetch_delay();
                this.fetcher = setTimeout(()=>{this.fetch_bytes()}, this.fetch_delay);
            }
        },
        ()=>{
            console.log("Data fetching failed");
            this.destroy();
        }
    )
};

//when this is called we start to pool data periodically via specification
MeekStream.prototype.start_periodical_fetcher = function(){
    if(this.fetcher === undefined) {
        this.fetch_delay = initial_fetch_delay;
        this.fetcher = setTimeout(()=>{this.fetch_bytes()}, this.fetch_delay)
    }
};

//stops periodical data fetching
MeekStream.prototype.stop_periodical_fetcher = function(){
    if(this.fetcher !== undefined) {
        clearTimeout(this.fetcher);
        this.fetcher = undefined;
        this.fetch_delay = undefined;
    }
};

//increases the fetch delay
MeekStream.prototype.increase_fetch_delay = function(){
    if(this.fetch_delay !== undefined && this.fetch_delay < maximum_pooling_delay)
    {
        this.fetch_delay = Math.round(this.fetch_delay*1.5);
        if(this.fetch_delay>maximum_pooling_delay){
            this.fetch_delay = maximum_pooling_delay;
        }
    }
};

//sets the on_data_ready callback
MeekStream.prototype.set_on_pass_upstream_fun = function (callback) {
    this.on_bytes_ready = callback;
};

MeekStream.prototype.send_downstream_fun = function (data) {
    return this.send_bytes(data);
};
