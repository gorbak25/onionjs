/*
Connect to an Onion Router using TLS
If the connection succeeds the tor protocol implementation will need to use the v3 in-protocol tor handshake
TLS Fragmentation is handled by forge's TLS engine

It calls a callback on fully received TOR cells - it will fragment the incoming data stream into single cells for higher processing layers
Only fully crafted tor cells are expected to be send downstream from here - higher layers need to apply proper padding, ciphering and output buffering
*/

var verbose_cells = false; //if true shows the received and transmitted cells

////////////////  COPY PASTE CODE BEGIN  ////////////////////////
//A Fast FIFO queue from https://github.com/creationix/fastqueue

function Queue() {
  this.head = [];
  this.tail = [];
  this.index = 0;
  this.headLength = 0;
  this.length = 0;
}

// Get an item from the front of the queue.
Queue.prototype.shift = function () {
  if (this.index >= this.headLength) {
    // When the head is empty, swap it with the tail to get fresh items.
    var t = this.head;
    t.length = 0;
    this.head = this.tail;
    this.tail = t;
    this.index = 0;
    this.headLength = this.head.length;
    if (!this.headLength) {
      return;
    }
  }

  // There was an item in the head, let's pull it out.
  var value = this.head[this.index];
  // And remove it from the head
  if (this.index < 0) {
    delete this.head[this.index++];
  }
  else {
    this.head[this.index++] = undefined;
  }
  this.length--;
  return value;
};

// Insert a new item at the front of the queue.
Queue.prototype.unshift = function (item) {
  this.head[--this.index] = item;
  this.length++;
  return this;
};

// Push a new item on the end of the queue.
Queue.prototype.push = function (item) {
  // Pushes always go to the write-only tail
  this.length++;
  this.tail.push(item);
  return this;
};

////////////////  COPY PASTE CODE END  ////////////////////////

//generates a random SNI
function generateRandomSNI(){
  return "www."+makeRandomString(21).toLowerCase()+".com";
}

//return tls cipher suites which will be used in the tls handshake
function getTorInitialClientCipherSuites(){
  //this combination tells the onion router that we want
  //to use the v3 or v2 tor handshake
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

//represents a TLS tor connection over a meek data stream
//downstream_processor is an object representing a lower processing layer, it implements at least three methods:
//send_downstream_fun - passes the data to lower processing layers
//set_on_pass_upstream_fun - sets the callback function responsible for passing the data to higher processing layers
//destroy - finishes the connection
function TLS_TOR_Connection(lower_processor){

  this.lower_processor = lower_processor;

  this.input_buffer = forge.util.createBuffer(); //lower layer upstream buffer
  this.cell_buffer = forge.util.createBuffer(); //cell buffer
  /* Cell states:
  0 - no data in cell_buffer -> expected circ_id
  1 - received circuit ID -> length depends on the link version protocol(2 bytes at the beginning) - expected command
  2 - received command -> expected payload length
  3 - payload length received -> waiting for payload - if succeed flush data to higher layers and move to state 0
   */
  this.cell_state = 0;
  this.tor_link_protocol_version = 3;
  this.CIRCID_LEN = 2; //2 bytes for link version <=3, 4 bytes for link version>3
  this.PAYLOAD_LEN = 509;
  this.cell_expected_payload_len = 509; //used for variable length cells

  //create the TLS connection
  this.tls_connection = forge.tls.createConnection({
    server: false,
    caStore: [],
    sessionCache: {},
    cipherSuites: getTorInitialClientCipherSuites(),
    virtualHost: generateRandomSNI(),
    verify: ((con, ver, depth, certs)=>{return this.verify_tls_certificate(con, ver, depth, certs);}),
    tlsDataReady: function(connection) {lower_processor.send_downstream_fun.bind(lower_processor)(connection.tlsData.getBytes());},
  });

  //contains whether the asynchronous cell formatter was initialized
  this.processing_loop_initialized = false;

  //contains the unprocessed cell queue --- necessary to do rate throtling
  this.cell_queue = new Queue;

  //a queue for cells to be send --- necessary to synchronize the asynchronous code
  this.send_queue = new Queue;

  //contains whether the cell sender was initialized
  this.sending_loop_initialized = false;

  //setup downstream handler
  lower_processor.set_on_pass_upstream_fun(this.tls_connection.process.bind(this.tls_connection));
  //start the tls handshake process
  var tor_connection = this;
  this.ready = new Promise(
    function(resolve,reject){
      //setup handlers
      tor_connection.tls_connection.connected = function(){
        console.log("Connected to onion router");
        //setup error handlers
        tor_connection.tls_connection.error = tor_connection.on_tls_error.bind(tor_connection);
        tor_connection.tls_connection.closed = tor_connection.on_tls_closed.bind(tor_connection);
        //setup data ready handler
        tor_connection.tls_connection.dataReady = (()=>{tor_connection.on_tls_deciphered_data_process(tor_connection.tls_connection.data.getBytes());});
        //resolve the promise
        resolve();
      };
      tor_connection.tls_connection.error = function(connection, error) {
        console.log('TLS/TOR error occured during initial handshake: ', error);
        tor_connection.lower_processor.destroy();
        reject();
      };
      tor_connection.tls_connection.closed = function(connection) {
        console.log('TOR node disconnected during initial handshake');
        lower_processor.destroy();
        reject();
      };
      //negotiate a tls session
      tor_connection.tls_connection.handshake();
    }
  );
}

TLS_TOR_Connection.prototype.verify_tls_certificate = function (forge_connection, verified, depth, certs) {
  this.tls_server_certificate = certs[0];

  if(certs.length != 1)
  {
    return {
      alert: forge.tls.Alert.Description.bad_certificate,
      message: 'Unsupported tor handshake v1.'
    };
  }
  /* Conditions for the v3 handshake
    * The certificate is self-signed
    * Some component other than "commonName" is set in the subject or
      issuer DN of the certificate.
    * The commonName of the subject or issuer of the certificate ends
      with a suffix other than ".net".
    * The certificate's public key modulus is longer than 1024 bits.
   */
  var is_self_signed_condition = this.tls_server_certificate.isIssuer(this.tls_server_certificate);
  //good enough check for now :P
  var component_condition =
    (this.tls_server_certificate.subject.attributes.length > 1) ||
    (this.tls_server_certificate.issuer.attributes.length > 1);
  var common_name_condition =
    (!this.tls_server_certificate.subject.getField('CN').value.endsWith('.net')) ||
    (!this.tls_server_certificate.issuer.getField('CN').value.endsWith('.net'));
  var pub_key_modulus_condition = this.tls_server_certificate.publicKey.n.bitLength() > 1024;

  var is_v3_handshake =
    is_self_signed_condition ||
    component_condition ||
    common_name_condition ||
    pub_key_modulus_condition;

  if(!is_v3_handshake)
  {
    return {
      alert: forge.tls.Alert.Description.bad_certificate,
      message: 'Unsupported tor handshake v2.'
    };
  }

  console.log("TOR handshake v3 detected");

  //we trust the certificate
  return true;
};

TLS_TOR_Connection.prototype.change_tor_link_version = function (version) {
  if(version >= 3) { //tor v3 handshake requires link version >= 3
    this.tor_link_protocol_version = version;
    if(this.tor_link_protocol_version > 3)
    {
      this.CIRCID_LEN = 4;
    }
    else
    {
      this.CIRCID_LEN = 2;
    }
  }else{
    console.log("Trying to set unsupported link protocol version");
  }
};

//sends out crafted cells to higher processing layers but no more than 80 cells per call
TLS_TOR_Connection.prototype.pass_upstream_rate_throthler = function (){
  if(this.cell_queue.length > 0)
  {
    var i=0;
    while(i<80 && this.cell_queue.length > 0)
    {
      i+=1;
      var cur = this.cell_queue.shift();
      if(verbose_cells) {
        console.log("RECEIVED CELL: ", btoa(cur));
      }
      this.on_data_ready(cur);
    }
  }
};

//extracts at most 4 cells from the input buffer and places them into the cell queue
TLS_TOR_Connection.prototype.cell_disector_step = function(){
  //try to extract at most 4 full tor cells
  /* Cell states:
  0 - no data in cell_buffer -> expected circ_id
  1 - received circuit ID -> length depends on the link version protocol(2 bytes at the beginning) - expected command
  2 - received command -> expected payload length
  3 - payload length received -> waiting for payload - if succeed flush data to higher layers and move to state 0
   */
   var i = 0;
  while(i<64 && this.input_buffer.length() > 0) {
    if (this.cell_state === 0) //obtain circuit id
    {
      if(this.input_buffer.length() >= this.CIRCID_LEN)
      {
        this.cell_buffer.putBytes(this.input_buffer.getBytes(this.CIRCID_LEN));
        this.cell_state = 1;
      }
      else{
        break;
      }
    }
    if (this.cell_state === 1) // obtain command
    {
      if(this.input_buffer.length() >= 1)
      {
        var command = Number(this.input_buffer.getByte());
        this.cell_buffer.putByte(command);

        //now we can determine whether we have a variable length cell or fixed length cell
        if(this.tor_link_protocol_version >= 2 && command === 7)
        {
          this.cell_state = 2; //variable len
        }
        else if(this.tor_link_protocol_version >= 3 && command >= 128)
        {
          this.cell_state = 2; //variable len
        }
        else //fixed len cell detected
        {
          this.cell_state = 3; //skip length obtaining
          this.cell_expected_payload_len = this.PAYLOAD_LEN;
        }
      }
      else{
        break;
      }
    }
    if (this.cell_state === 2) //obtain payload length
    {
      if(this.input_buffer.length() >= 2)
      {
        this.cell_expected_payload_len = this.input_buffer.getInt16();
        this.cell_buffer.putInt16(this.cell_expected_payload_len);
        this.cell_state = 3;
      }
      else{
        break;
      }
    }
    if(this.cell_state === 3) //obtain payload
    {
      if(this.input_buffer.length() >= this.cell_expected_payload_len)
      {
        this.cell_buffer.putBytes(this.input_buffer.getBytes(this.cell_expected_payload_len));
        this.input_buffer.compact();
        this.cell_state = 0;
        var crafted_cell = this.cell_buffer.getBytes();

        this.cell_queue.push(crafted_cell);
        i+=1;
      }
      else{
        break;
      }
    }
  }
};

TLS_TOR_Connection.prototype.on_tls_deciphered_data_process = function (bytes) {
  //buffer the data
  this.input_buffer.putBytes(bytes);

  //if the processing loop was not started start it
  if(this.processing_loop_initialized === false)
  {
    this.processing_loop_initialized=true;
    setInterval(()=>{ //just to limit the data rate
      this.pass_upstream_rate_throthler();
      },50);

    setInterval(()=>{ //just to limit the data rate
      this.cell_disector_step();
    },50);
  }
};

//tls error handler after the tls handshake
TLS_TOR_Connection.prototype.on_tls_error = function (connection, error) {
  console.log('TLS error occurred: ', error);
  this.input_buffer.clear();
  this.cell_buffer.clear();
  this.lower_processor.destroy();
};

//tls connection closed handler after the tls handshake
TLS_TOR_Connection.prototype.on_tls_closed = function (connection) {
  console.log('TLS connection was closed');
  this.input_buffer.clear();
  this.cell_buffer.clear();
  this.lower_processor.destroy();
};

TLS_TOR_Connection.prototype.send_downstream_fun = function (data){
  if(verbose_cells) {
  console.log("SENDING CELL: ", btoa(data));
  }

  this.send_queue.push(data);

  if(this.sending_loop_initialized === false)
  {
    this.sending_loop_initialized = true;
    setInterval(()=>{
      if(this.send_queue.length > 0)
      {
        this.tls_connection.prepare(this.send_queue.shift());
      }
    },50);
  }
};

TLS_TOR_Connection.prototype.set_on_pass_upstream_fun = function (callback) {
  this.on_data_ready = callback;
};

TLS_TOR_Connection.prototype.destroy = function () {
  this.tls_connection.close();
  this.input_buffer.clear();
  this.cell_buffer.clear();
  this.lower_processor.destroy();
};
