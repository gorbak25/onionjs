/*
Implement the tor protocol on top of an existing connection to an onion relay
This implementation expects to receive full tor cells without any kind of fragmentation
It will send downstream correctly formed tor cells

First it will make the tor v3 handshake.
If it succeeds it will expose:
A circuit interface to create circuits
Circuits can create data streams -> we will expose 2 kinds of data streams:
TCP exit streams
TCP directory streams
Circuits will expose a DNS resolve interface
*/

function pad_payload_buffer(buffer)
{
    while(buffer.length() < PAYLOAD_LEN)
    {
        buffer.putByte(0);
    }
}

var tor_error_handlers = {
    "versions_decode_error": "close_connection",
    "announcing_invalid_version": "close_connection",
    "unexpected_cell_type": "close_connection",
    "not_supported_versions": "close_connection",
    "not_supported_cert": "close_connection",
    "more_than_one_cert_of_the_same_type": "close_connection",
    "cert_expired": "close_connection",
    "invalid_certs": "close_connection",
    "circuit_creation_failure": "close_connection" //good enough for now, later just try again :P
};

function TOR_Error(handler_name, user_message) {
    this.handler_name = handler_name;
    this.user_message = user_message;
}

//---------------------------------------------------------------

//padding cells are used for keep alive purposes
function TOR_Payload_Padding(){

}

TOR_Payload_Padding.prototype.loadBytes = function(bytes)
{
};

TOR_Payload_Padding.prototype.dumpBytes = function()
{
    var buffer = forge.util.createBuffer();
    pad_payload_buffer(buffer);
    return buffer.getBytes();
};

//---------------------------------------------------------------

function TOR_Payload_Create(){

}

function TOR_Payload_Created(){

}

//---------------------------------------------------------------

/*
The relay commands are:
         1 -- RELAY_BEGIN     [forward]
         2 -- RELAY_DATA      [forward or backward]
         3 -- RELAY_END       [forward or backward]
         4 -- RELAY_CONNECTED [backward]
         5 -- RELAY_SENDME    [forward or backward] [sometimes control]
         6 -- RELAY_EXTEND    [forward]             [control]
         7 -- RELAY_EXTENDED  [backward]            [control]
         8 -- RELAY_TRUNCATE  [forward]             [control]
         9 -- RELAY_TRUNCATED [backward]            [control]
        10 -- RELAY_DROP      [forward or backward] [control]
        11 -- RELAY_RESOLVE   [forward]
        12 -- RELAY_RESOLVED  [backward]
        13 -- RELAY_BEGIN_DIR [forward]
        14 -- RELAY_EXTEND2   [forward]             [control]
        15 -- RELAY_EXTENDED2 [backward]            [control]

        32..40 -- Used for hidden services; see rend-spec.txt.

 */

function TOR_Relay_CMD_Relay_Begin(){

}

function TOR_Relay_CMD_Relay_Data(){
    this.data = "";
}

TOR_Relay_CMD_Relay_Data.prototype.dumpBytes = function()
{
    return this.data;
};

TOR_Relay_CMD_Relay_Data.prototype.loadBytes = function(bytes)
{
    this.data = bytes;
};

TOR_Relay_CMD_Relay_Data.prototype.setPayload = function(bytes)
{
    this.data = bytes;
};

function TOR_Relay_CMD_Relay_End(){

}

function TOR_Relay_CMD_Relay_Connected(){

}

function TOR_Relay_CMD_Relay_Sendme(){

}

TOR_Relay_CMD_Relay_Sendme.prototype.dumpBytes = function(){
    return "";
};

function TOR_Relay_CMD_Relay_Extend(){

}

function TOR_Relay_CMD_Relay_Extended(){

}

function TOR_Relay_CMD_Relay_Truncate(){

}

function TOR_Relay_CMD_Relay_Truncated(){

}

function TOR_Relay_CMD_Relay_Drop(){

}

function TOR_Relay_CMD_Relay_Resolve(){

}

function TOR_Relay_CMD_Relay_Resolved(){

}

function TOR_Relay_CMD_Relay_Begin_Dir(){

}

TOR_Relay_CMD_Relay_Begin_Dir.prototype.dumpBytes = function(){
    return "";
};

function TOR_Relay_CMD_Relay_Extend2(){

}

function TOR_Relay_CMD_Relay_Extended2(){

}

var relay_cmd_processors = //defines the relay command decoders for a given command id
    {
        1: TOR_Relay_CMD_Relay_Begin,
        2: TOR_Relay_CMD_Relay_Data,
        3: TOR_Relay_CMD_Relay_End,
        4: TOR_Relay_CMD_Relay_Connected,
        5: TOR_Relay_CMD_Relay_Sendme,
        6: TOR_Relay_CMD_Relay_Extend,
        7: TOR_Relay_CMD_Relay_Extended,
        8: TOR_Relay_CMD_Relay_Truncate,
        9: TOR_Relay_CMD_Relay_Truncated,
        10: TOR_Relay_CMD_Relay_Drop,
        11: TOR_Relay_CMD_Relay_Resolve,
        12: TOR_Relay_CMD_Relay_Resolved,
        13: TOR_Relay_CMD_Relay_Begin_Dir,
        14: TOR_Relay_CMD_Relay_Extend2,
        15: TOR_Relay_CMD_Relay_Extended2
    };

//maps defined payload constructors to id numbers
var relay_cmd_processor_to_id = {};
for(var id in relay_cmd_processors)
{
    relay_cmd_processor_to_id[relay_cmd_processors[id]] = id;
}

//represents a parsed relay payload but it can be encrypted
function TOR_Payload_Relay_Generic_Contents(bytes){
    this.relay_cmd = 0;
    this.recognized = 0;
    this.stream_id = 0;
    this.digest = '\x00'.repeat(4);
    this.payload_raw_len = 0;
    this.payload_raw = "";

    this.payload = undefined; //a decoded payload object

    if(bytes !== undefined)
    {
        this.loadBytes(bytes);
    }
}

//dissects a relay cell payload - dissection of the contained data must be started AFTER the contents were confirmed to be valid
TOR_Payload_Relay_Generic_Contents.prototype.loadBytes = function(bytes)
{
    var buffer = forge.util.createBuffer(bytes);
    /*
        The payload of each unencrypted RELAY cell consists of:
            Relay command           [1 byte]
            'Recognized'            [2 bytes]
            StreamID                [2 bytes]
            Digest                  [4 bytes]
            Length                  [2 bytes]
            Data                    [PAYLOAD_LEN-11 bytes]
    */
    this.relay_cmd = buffer.getByte();
    this.recognized = buffer.getInt16();
    this.stream_id = buffer.getInt16();
    this.digest = buffer.getBytes(4);
    this.payload_raw_len = buffer.getInt16();
    this.payload_raw = buffer.getBytes();
};

TOR_Payload_Relay_Generic_Contents.prototype.dumpBytes = function()
{
    var buffer = forge.util.createBuffer();
    buffer.putByte(this.relay_cmd);
    buffer.putInt16(this.recognized);
    buffer.putInt16(this.stream_id);
    buffer.putBytes(this.digest);

    if(this.payload !== undefined)
    {
        this.payload_raw = this.payload.dumpBytes();
        this.payload_raw_len = this.payload_raw.length;
    }

    buffer.putInt16(this.payload_raw_len);
    buffer.putBytes(this.payload_raw);

    pad_payload_buffer(buffer);
    return buffer.getBytes();
};

//This function must be called only when we are sure that the contents are valid
TOR_Payload_Relay_Generic_Contents.prototype.decodePayloadRaw = function()
{
    this.payload = new relay_cmd_processors[this.relay_cmd]();
    this.payload.loadBytes(this.payload_raw_len, this.payload_raw);
};

TOR_Payload_Relay_Generic_Contents.prototype.setRelayCommand = function(command)
{
    this.payload = command;
    this.relay_cmd = Number(relay_cmd_processor_to_id[command.constructor]);
};

//encapsulates relay data
function TOR_Payload_Relay(){
    //the payload can or can not be encrypted
    //so the interpretation of this data the job of the higher processing layers
    this.cell_data = "";
}

TOR_Payload_Relay.prototype.loadBytes = function(bytes)
{
    this.cell_data = bytes;
};

TOR_Payload_Relay.prototype.dumpBytes = function()
{
    var buffer = forge.util.createBuffer();
    buffer.putBytes(this.cell_data);
    pad_payload_buffer(buffer);
    return buffer.getBytes();
};

TOR_Payload_Relay.prototype.encryptWithCipher = function(cipher){
    //ensure proper padding
    this.ensurePadding();

    //pass cleartext to the cipher
    cipher.update(forge.util.createBuffer(this.cell_data));
    //console.dir(cipher)

    //extract the ciphertext
    var crypted_buff = forge.util.createBuffer();
    crypted_buff.putBytes(cipher.output.getBytes());

    //setup the payload
    this.cell_data = crypted_buff.getBytes();

    console.log("ENCRYPTED_LEN", this.cell_data.length);
};

TOR_Payload_Relay.prototype.decryptWithDecipher = function(decipher){
    decipher.update(forge.util.createBuffer(this.cell_data));

    this.cell_data = decipher.output.getBytes();
};

TOR_Payload_Relay.prototype.generateDigest = function(message_digest_obj){
    this.ensurePadding();

    var buffer = forge.util.createBuffer(this.cell_data);

    message_digest_obj.update(buffer.getBytes(1+2+2)); //CMD + Recognized + StreamID

    buffer.getBytes(4); //ignore the digest
    message_digest_obj.update('\x00'.repeat(4));

    message_digest_obj.update(buffer.getBytes());

    return message_digest_obj.digest().getBytes(4);
};

TOR_Payload_Relay.prototype.ensurePadding = function()
{
    //ensure proper padding
    if(this.cell_data.length < PAYLOAD_LEN)
    {
        this.cell_data = this.dumpBytes();
    }
};

TOR_Payload_Relay.prototype.disectData = function()
{
    return new TOR_Payload_Relay_Generic_Contents(this.cell_data);
};

//---------------------------------------------------------------

function TOR_Payload_Destroy(){

}

//---------------------------------------------------------------

function TOR_Payload_Create_Fast(){
    this.key_material = forge.random.getBytesSync(HASH_LEN);
}

TOR_Payload_Create_Fast.prototype.dumpBytes = function(){
    var buffer = forge.util.createBuffer();

    buffer.putBytes(this.key_material);
    pad_payload_buffer(buffer);

    return buffer.getBytes();
};

//---------------------------------------------------------------

function TOR_Payload_Created_Fast(){
    this.key_material = undefined;
    this.derivative_key_material = undefined;
}

TOR_Payload_Created_Fast.prototype.loadBytes = function(bytes){
    var buffer = forge.util.createBuffer();
    buffer.putBytes(bytes);

    var HASH_LEN=20;
    this.key_material = buffer.getBytes(HASH_LEN);
    this.derivative_key_material = buffer.getBytes(HASH_LEN);
};

//---------------------------------------------------------------

function TOR_Payload_Versions() {
    this.supported_versions = [];
}

TOR_Payload_Versions.prototype.loadBytes = function(bytes){
  var buffer = forge.util.createBuffer();
  buffer.putBytes(bytes);
  var len = buffer.getInt16();

  if(buffer.length()%2 === 1 || len !== buffer.length())
  {
      throw new TOR_Error(tor_error_handlers.versions_decode_error, "Malformed versions packet");
  }

  while(buffer.length() > 0)
  {
      this.supported_versions.push(buffer.getInt16());
  }
  buffer.clear();
};

TOR_Payload_Versions.prototype.dumpBytes = function () {
    var buffer = forge.util.createBuffer();
    buffer.putInt16(this.supported_versions.length*2);
    for(var i in this.supported_versions)
    {
        buffer.putInt16(this.supported_versions[i]);
    }
    return buffer.getBytes();
};

TOR_Payload_Versions.prototype.addVersion = function (v) {
  if(v <= 0 || v >= 6)
  {
      throw new TOR_Error(tor_error_handlers.announcing_invalid_version, "Current link protocol versions are: 1-5");
  }
  if(v <= 2)
  {
      throw new TOR_Error(tor_error_handlers.announcing_invalid_version, "The v3 handshake requires link protocol version greater than 2");
  }
  this.supported_versions.push(v);
};

//---------------------------------------------------------------

function TOR_Net_Info_Address(bytes){
    this.type = undefined;
    this.value = undefined;

    this.addr = undefined; //a high level representation of the address

    if(bytes !== undefined)
    {
        this.loadBytes(bytes);
    }
}

TOR_Net_Info_Address.prototype.loadBytes = function(bytes){
    var buffer = forge.util.createBuffer();
    buffer.putBytes(bytes);

    this.type = buffer.getByte();
    this.value = buffer.getBytes(buffer.getByte());

    /*
     "Type" is one of:
      0x00 -- Hostname
      0x04 -- IPv4 address
      0x06 -- IPv6 address
      0xF0 -- Error, transient
      0xF1 -- Error, nontransient
     */

    var type_hostname = 0x00;
    var type_ipv4 = 0x04;
    var type_ipv6 = 0x06;
    var type_err_transient = 0xf0;
    var type_err_non_transient = 0xf1;

    if(this.type === type_hostname)
    {
        this.addr = this.value;
    }
    if(this.type === type_ipv4)
    {
        this.addr = this.value.charCodeAt(0)+"."+this.value.charCodeAt(1)+"."+this.value.charCodeAt(2)+"."+this.value.charCodeAt(3);
    }
};

TOR_Net_Info_Address.prototype.dumpBytes = function(){
    var buffer = forge.util.createBuffer();

    if(this.addr !== undefined)
    {
        var splitted = this.addr.split(".");
        if(splitted.length !== 4)
        {
            this.type = 0x00; //type hostname
            this.value = this.addr;
        }
        else if(
            splitted[0].match(/^[0-9]+$/) !== null &&
            splitted[1].match(/^[0-9]+$/) !== null &&
            splitted[2].match(/^[0-9]+$/) !== null &&
            splitted[3].match(/^[0-9]+$/) !== null)
        {
            this.type = 0x04; //type ipv4
            var fjs = ((a)=>{return String.fromCharCode(parseInt(a))});
            this.value = fjs(splitted[0])+fjs(splitted[1])+fjs(splitted[2])+fjs(splitted[3]);
        }
    }

    buffer.putByte(this.type);
    buffer.putByte(this.value.length);
    buffer.putBytes(this.value);
    return buffer.getBytes();
};

function TOR_Payload_Net_Info(){
    this.timestamp = undefined;
    this.other_or_address = undefined;
    this.this_or_addresses = [];
}

TOR_Payload_Net_Info.prototype.retrieveBytesAddressFromBuffer = function(buffer){
    var addr = forge.util.createBuffer();

    addr.putByte(buffer.getByte());
    var len = buffer.getByte();
    addr.putByte(len);
    addr.putBytes(buffer.getBytes(len));

    return addr.getBytes();
};

TOR_Payload_Net_Info.prototype.loadBytes = function(bytes){
    var buffer = forge.util.createBuffer();
    buffer.putBytes(bytes);

    this.timestamp = new Date(buffer.getInt32()*1000);
    this.other_or_address = new TOR_Net_Info_Address(this.retrieveBytesAddressFromBuffer(buffer));
    var n_of_addresses = buffer.getByte();

    for(var i = 0; i<n_of_addresses; i++)
    {
        this.this_or_addresses.push(new TOR_Net_Info_Address(this.retrieveBytesAddressFromBuffer(buffer)));
    }

    buffer.clear();
};

TOR_Payload_Net_Info.prototype.dumpBytes = function(){
    var buffer = forge.util.createBuffer();

    this.timestamp = Number(((+new Date())/1000).toFixed(0));
    buffer.putInt32(this.timestamp);
    buffer.putBytes(this.other_or_address.dumpBytes());
    buffer.putByte(this.this_or_addresses.length);
    for(var i = 0; i<this.this_or_addresses.length; i++)
    {
        buffer.putBytes(this.this_or_addresses[i].dumpBytes());
    }

    pad_payload_buffer(buffer);

    return buffer.getBytes();
};

TOR_Payload_Net_Info.prototype.setOtherAddr = function(addr){
    this.other_or_address = new TOR_Net_Info_Address();
    this.other_or_address.addr = addr;
};

TOR_Payload_Net_Info.prototype.getOtherAddr = function(){
    return this.other_or_address.addr;
};

TOR_Payload_Net_Info.prototype.appendThisAddr = function(addr){
    var data = new TOR_Net_Info_Address();
    data.addr = addr;
    this.this_or_addresses.push(data);
};

TOR_Payload_Net_Info.prototype.getAnyThisAddr = function(){
    return this.this_or_addresses[0].addr;
};

//---------------------------------------------------------------

//just consider it as a wrapper for relay cells
function TOR_Payload_Relay_Early(){
    this.relay_cell = undefined;
}

TOR_Payload_Relay_Early.prototype.loadBytes = function(bytes){
    this.relay_cell = new TOR_Payload_Relay();
    this.relay_cell.loadBytes(bytes);
};

TOR_Payload_Relay_Early.prototype.dumpBytes = function(){
  return this.relay_cell.dumpBytes();
};

TOR_Payload_Relay_Early.prototype.getRelayCell = function(){
    return this.relay_cell;
};

TOR_Payload_Relay_Early.prototype.encapsulateRelayCell = function(cell){
    this.relay_cell = cell;
};

//---------------------------------------------------------------

function TOR_Payload_Create2() {

}

function TOR_Payload_Created2() {

}

function TOR_Payload_Padding_Negotiate() {

}

function TOR_Payload_V_Padding() {

}

//---------------------------------------------------------------

function Ed25519_Certificate_Extension(bytes){
    var buffer = forge.util.createBuffer();
    buffer.putBytes(bytes);

    this.ext_len = buffer.length()-2;
    this.ext_type = buffer.getByte();
    this.ext_flags = buffer.getByte();
    this.ext_data = buffer.getBytes(this.ext_len);
}

function Ed25519_Certificate(bytes) {
    var buffer = forge.util.createBuffer();
    buffer.putBytes(bytes);

    this.version = buffer.getByte();
    this.cert_type = buffer.getByte();
    this.expiration_date = new Date(buffer.getInt32()*3600*1000);
    this.cert_key_type = buffer.getByte();
    this.certified_key = buffer.getBytes(32);
    this.n_extensions = buffer.getByte();
    this.extensions = [];
    for(var i = 0; i<this.n_extensions; i++)
    {
        var ext_len = buffer.getInt16();
        this.extensions.push(new Ed25519_Certificate_Extension(buffer.getBytes(ext_len+2)));
    }
    this.signature = buffer.getBytes(64);

    var sign_buffer = forge.util.createBuffer();
    sign_buffer.putBytes(bytes);
    //somehow the signature validates when I ignore the prefix...
    this.to_sign = /*"Tor node signing key certificate v1" + */sign_buffer.getBytes(sign_buffer.length()-64);
    sign_buffer.clear();
}

Ed25519_Certificate.prototype.verifyECDSASignature = function(ed25519_bytes_key)
{
    //Verify the signature
    //TODO: optimize the conversion
    return nacl.sign.detached.verify(
        nacl.util.decodeBase64(btoa(this.to_sign)),
        nacl.util.decodeBase64(btoa(this.signature)),
        nacl.util.decodeBase64(btoa(ed25519_bytes_key)));
};

function RSA_Ed25519_Cross_Certificate(bytes) {
    var buffer = forge.util.createBuffer();
    buffer.putBytes(bytes);

    this.ed25519_key = buffer.getBytes(32);
    this.expiration_date = new Date(buffer.getInt32()*3600*1000);
    this.siglen = buffer.getByte();
    this.signature = buffer.getBytes(this.siglen);

    var sign_buffer = forge.util.createBuffer();
    sign_buffer.putBytes(bytes);
    this.to_sign = "Tor TLS RSA/Ed25519 cross-certificate"+sign_buffer.getBytes(sign_buffer.length()-this.siglen-1);
    sign_buffer.clear();
}

RSA_Ed25519_Cross_Certificate.prototype.verifyRSASignature = function(rsa_key)
{
    var md = forge.md.sha256.create();
    md.update(this.to_sign);
    var digest = md.digest().getBytes();

    return rsa_key.verify(digest, this.signature, null);
};

function TOR_Payload_Certs() {
    this.number_of_certs = 0;
}

TOR_Payload_Certs.prototype.loadBytes = function(bytes) {
    //"define" certs variables
    this.cert_link = undefined;
    this.cert_id = undefined;
    this.cert_id_to_signing = undefined;
    this.cert_signing_to_link = undefined;
    this.cert_rsa_to_ed25519 = undefined;

    var buffer = forge.util.createBuffer();
    buffer.putBytes(bytes);
    buffer.getInt16(); //ignore the len

    this.number_of_certs = buffer.getByte();

    for(var i = 0; i<this.number_of_certs; i++) //decode the certificates
    {
        var cert_type = buffer.getByte();
        console.log("Received certificate type: ", cert_type);
        var cert_len = buffer.getInt16();
        var raw_certificate_data = buffer.getBytes(cert_len);

        if(cert_type >= 1 && cert_type <= 3)
        {
            var cert_buffer = forge.util.createBuffer();
            cert_buffer.putBytes(raw_certificate_data);

            var asn1 = forge.asn1.fromDer(cert_buffer);
            var cert = forge.pki.certificateFromAsn1(asn1, true);

            var now = new Date();
            if(now < cert.validity.notBefore || now > cert.validity.notAfter) {
                throw new TOR_Error(tor_error_handlers.cert_expired, "CERT cell contains expired or not valid yet certificates");
            }

            if(cert_type === 1)
            {
                if(this.cert_link !== undefined)
                {
                    throw new TOR_Error(tor_error_handlers.more_than_one_cert_of_the_same_type, "CERT cell contains more than one Link certificate");
                }
                this.cert_link = cert;
            }
            else if(cert_type === 2)
            {
                if(this.cert_id !== undefined)
                {
                    throw new TOR_Error(tor_error_handlers.more_than_one_cert_of_the_same_type, "CERT cell contains more than one ID certificate");
                }
                this.cert_id = cert;
            }
            else
            {
                throw new TOR_Error(tor_error_handlers.not_supported_cert, "AUTHENTICATION CERTIFICATES NOT SUPPORTED");
            }
        }

        if(cert_type >= 4 && cert_type <= 6)
        {
            var cert = new Ed25519_Certificate(raw_certificate_data);
            var now = new Date();
            if(cert.expiration_date < now) {
                throw new TOR_Error(tor_error_handlers.cert_expired, "CERT cell contains expired certificates");
            }

            if(cert_type === 4)
            {
                if(this.cert_id_to_signing !== undefined)
                {
                    throw new TOR_Error(tor_error_handlers.more_than_one_cert_of_the_same_type, "CERT cell contains more than one ID->Signing certificate");
                }
                this.cert_id_to_signing = cert;
            }
            else if(cert_type === 5)
            {
                if(this.cert_signing_to_link !== undefined)
                {
                    throw new TOR_Error(tor_error_handlers.more_than_one_cert_of_the_same_type, "CERT cell contains more than one Signing->Link certificate");
                }
                this.cert_signing_to_link = cert;
            }
            else
            {
                throw new TOR_Error(tor_error_handlers.not_supported_cert, "AUTHENTICATION CERTIFICATES NOT SUPPORTED");
            }
        }

        if(cert_type === 7)
        {
            if(this.cert_rsa_to_ed25519 !== undefined)
            {
                throw new TOR_Error(tor_error_handlers.more_than_one_cert_of_the_same_type, "CERT cell contains more than one RSA->ED25519 cross certificate");
            }
            this.cert_rsa_to_ed25519 = new RSA_Ed25519_Cross_Certificate(raw_certificate_data);
            var now = new Date();
            if(this.cert_rsa_to_ed25519.expiration_date < now) {
                throw new TOR_Error(tor_error_handlers.cert_expired, "RSA->ED25519 cross certificate is expired");
            }
        }
    }

    buffer.clear();
};

//from the received certificates tries to establish the identity of the responder
//whether we want to trust this identity depends of the higher layers of data processing
TOR_Payload_Certs.prototype.establishIdentity = function(server_tls_certificate) {
    if(this.cert_id !== undefined && this.cert_id_to_signing !== undefined && this.cert_signing_to_link !== undefined && this.cert_rsa_to_ed25519 !== undefined)
    {
        /*
           To authenticate the responder as having a given Ed25519, RSA identity key
           combination, the initiator MUST check the following:
             * The CERTS cell contains exactly one CertType 2 "ID" certificate.     OK
             * The CERTS cell contains exactly one CertType 4 Ed25519               OK
               "Id->Signing" cert.
             * The CERTS cell contains exactly one CertType 5 Ed25519               OK
               "Signing->link" certificate.
             * The CERTS cell contains exactly one CertType 7 "RSA->Ed25519"        OK
               cross-certificate.
             * All X.509 certificates above have validAfter and validUntil dates;   OK
               no X.509 or Ed25519 certificates are expired.
             * All certificates are correctly signed.                               OK
             * The certified key in the Signing->Link certificate matches the       OK
               SHA256 digest of the certificate that was used to
               authenticate the TLS connection.
             * The identity key listed in the ID->Signing cert was used to          OK
               sign the ID->Signing Cert.
             * The Signing->Link cert was signed with the Signing key listed        OK
               in the ID->Signing cert.
             * The RSA->Ed25519 cross-certificate certifies the Ed25519             OK
               identity, and is signed with the RSA identity listed in the
               "ID" certificate.
             * The certified key in the ID certificate is a 1024-bit RSA key.       OK
             * The RSA ID certificate is correctly self-signed.                     OK
         */

        console.log("Trying to determine ED25519 and RSA identity");
        if
        (
            this.cert_id.isIssuer(this.cert_id) &&
            this.cert_id.verify(this.cert_id) &&
            this.cert_id.publicKey.n.bitLength() === 1024 &&
            ( //signing->link certified key check
                (
                    ()=>
                    {
                        var md = forge.md.sha256.create();
                        md.update(forge.asn1.toDer(forge.pki.certificateToAsn1(server_tls_certificate)).getBytes());
                        return md.digest().getBytes();
                    }
                )() === this.cert_signing_to_link.certified_key
            ) &&
            ( //rsa cross cert signature check
                this.cert_rsa_to_ed25519.verifyRSASignature(this.cert_id.publicKey)
            ) &&
            ( //in case the "signed with" extension is present check if it matches the ed25519 identity
                this.cert_id_to_signing.n_extensions > 0 ? this.cert_id_to_signing.extensions[0].ext_data === this.cert_rsa_to_ed25519.ed25519_key : true
            ) &&
            ( //check if the master ed25519 identity key was used to sign the ed25519 signing key
                this.cert_id_to_signing.verifyECDSASignature(this.cert_rsa_to_ed25519.ed25519_key)
            ) &&
            ( //check if the signing ed25519 key was used to sign the link certificate
                this.cert_signing_to_link.verifyECDSASignature(this.cert_id_to_signing.certified_key)
            )
        )
        {
            //checks were passed - now we can save some info for easy access
            this.identity_rsa = this.cert_id.publicKey;
            this.identity_ed25519_id = this.cert_rsa_to_ed25519.ed25519_key;
            this.identity_ed25519_signing = this.cert_id_to_signing.certified_key;
            //we do not need to save the link key as we are only an onion proxy

            console.log("Router's ed25519 identity is:", btoa(this.identity_ed25519_id));
        }
        else
        {
            throw new TOR_Error(tor_error_handlers.invalid_certs, "Invalid certificate signatures!");
        }
    }
    else if(this.cert_link !== undefined && this.cert_id !== undefined)
    {
        /*
            To authenticate the responder as having a given RSA identity only,
            the initiator MUST check the following:
                * The CERTS cell contains exactly one CertType 1 "Link" certificate.    OK
                * The CERTS cell contains exactly one CertType 2 "ID" certificate.      OK
                * Both certificates have validAfter and validUntil dates that           OK
                  are not expired.
                * The certified key in the Link certificate matches the                 OK
                  link key that was used to negotiate the TLS connection.
                * The certified key in the ID certificate is a 1024-bit RSA key.        OK
                * The certified key in the ID certificate was used to sign both         OK
                  certificates.
                * The link certificate is correctly signed with the key in the          OK
                  ID certificate
                * The ID certificate is correctly self-signed.
         */

        console.log("Trying to determine RSA identity");
        if
        (
            (forge.asn1.toDer(forge.pki.publicKeyToAsn1(server_tls_certificate.publicKey)).getBytes() ===
            forge.asn1.toDer(forge.pki.publicKeyToAsn1(this.cert_link.publicKey)).getBytes()) &&
            this.cert_id.publicKey.n.bitLength() === 1024 &&
            this.cert_id.verify(this.cert_link) &&
            this.cert_id.verify(this.cert_id) &&
            this.cert_id.isIssuer(this.cert_id)
        )
        {
            this.identity_rsa = this.cert_id.publicKey;
        }
        else
        {
            throw new TOR_Error(tor_error_handlers.invalid_certs, "Invalid certificate signatures!");
        }
    }

    var md = forge.md.sha1.create();
    md.update(forge.asn1.toDer(forge.pki.publicKeyToRSAPublicKey(this.identity_rsa)).getBytes());
    this.identity_fingerprint = md.digest().toHex();
    console.log("Router's rsa identity fingerprint is:", this.identity_fingerprint);

};

//---------------------------------------------------------------

function TOR_Payload_Auth_Challenge() {
    this.challenge = "";
    this.n_methods = 0;
    this.methods = [];
}

TOR_Payload_Auth_Challenge.prototype.loadBytes = function(bytes) {
    var buffer = forge.util.createBuffer();
    buffer.putBytes(bytes);
    buffer.getInt16(); //ignore the len

    this.challenge = buffer.getBytes(32);
    this.n_methods = buffer.getInt16();

    for(var i = 0; i<this.n_methods; i++)
    {
        this.methods.push(buffer.getInt16());
    }
    buffer.clear();
};

//---------------------------------------------------------------

function TOR_Payload_Authenticate() {

}

function TOR_Payload_Authorize() {

}

/* CELL TYPES:
    0 -- PADDING     (Padding)                 (See Sec 7.2)
    1 -- CREATE      (Create a circuit)        (See Sec 5.1)
    2 -- CREATED     (Acknowledge create)      (See Sec 5.1)
    3 -- RELAY       (End-to-end data)         (See Sec 5.5 and 6)
    4 -- DESTROY     (Stop using a circuit)    (See Sec 5.4)
    5 -- CREATE_FAST (Create a circuit, no PK) (See Sec 5.1)
    6 -- CREATED_FAST (Circuit created, no PK) (See Sec 5.1)
    8 -- NETINFO     (Time and address info)   (See Sec 4.5)
    9 -- RELAY_EARLY (End-to-end data; limited)(See Sec 5.6)
    10 -- CREATE2    (Extended CREATE cell)    (See Sec 5.1)
    11 -- CREATED2   (Extended CREATED cell)    (See Sec 5.1)
    12 -- PADDING_NEGOTIATE   (Padding negotiation)    (See Sec 7.2)

    Variable-length command values are:
    7 -- VERSIONS    (Negotiate proto version) (See Sec 4)
    128 -- VPADDING  (Variable-length padding) (See Sec 7.2)
    129 -- CERTS     (Certificates)            (See Sec 4.2)
    130 -- AUTH_CHALLENGE (Challenge value)    (See Sec 4.3)
    131 -- AUTHENTICATE (Client authentication)(See Sec 4.5)
    132 -- AUTHORIZE (Client authorization)    (Not yet used)
    */

var cell_payload_processors = //defines the payload decoders for a given command
    {
        0: TOR_Payload_Padding,
        1: TOR_Payload_Create,
        2: TOR_Payload_Created,
        3: TOR_Payload_Relay,
        4: TOR_Payload_Destroy,
        5: TOR_Payload_Create_Fast,
        6: TOR_Payload_Created_Fast,
        7: TOR_Payload_Versions,
        8: TOR_Payload_Net_Info,
        9: TOR_Payload_Relay_Early,
        10: TOR_Payload_Create2,
        11: TOR_Payload_Created2,
        12: TOR_Payload_Padding_Negotiate,
        128: TOR_Payload_V_Padding,
        129: TOR_Payload_Certs,
        130: TOR_Payload_Auth_Challenge,
        131: TOR_Payload_Authenticate,
        132: TOR_Payload_Authorize
    };

//maps defined payload constructors to id numbers
var payload_constructor_to_id = {};
for(var id in cell_payload_processors)
{
    payload_constructor_to_id[cell_payload_processors[id]] = id;
}

//represents a tor cell
function TOR_Cell(tor_link_version, cell_bytes){
    //create a raw cell
    this.circuit_id = 0;
    this.command = 0;
    if(tor_link_version > 3)
    {
        this.circ_id_len = 4;
    }
    else
    {
        this.circ_id_len = 2;
    }
    this.payload = {}; // a payload decoder

    if (cell_bytes !== undefined) //decode the cell if data is present
    {
        this.loadBytes(cell_bytes);
    }
}

TOR_Cell.prototype.setPayload = function (payload_obj) {
    this.payload = payload_obj;
    this.command = Number(payload_constructor_to_id[payload_obj.constructor]);
};

//loads a tor cell from bytes
TOR_Cell.prototype.loadBytes = function(cell_bytes){
    var buffer = forge.util.createBuffer();
    buffer.putBytes(cell_bytes);

    this.circuit_id = buffer.getInt(this.circ_id_len*8);
    this.command = Number(buffer.getByte());

    this.payload = new cell_payload_processors[this.command]();
    this.payload.loadBytes(buffer.getBytes()); //payload processor will need to care about variable length cells
};

//dumps a tor cell together with appropriate padding
TOR_Cell.prototype.dumpBytes = function(){
    var payload = this.payload.dumpBytes(); //payload processor will need to handle padding and length obtaining

    var buffer = forge.util.createBuffer();
    buffer.putInt(this.circuit_id, this.circ_id_len*8);
    buffer.putByte(this.command);
    buffer.putBytes(payload);

    return buffer.getBytes();
};

function TOR_Protocol(tor_connection)
{
    this.lower_processor = tor_connection;
    //CELL_TYPE -> function
    this.cell_handlers = {}; //if a handler here is present it will ignore the circuit router handlers, these handlers apply for ALL circuit ids
    //CIRCUIT ID to function
    this.circuit_router_handlers = {}; //these handlers route a tor cell payload to the appropriate circuit
    this.change_tor_link_version(3);
    this.lower_processor.set_on_pass_upstream_fun((bytes)=>{this.process_incoming_data(bytes);});
    this.ignore_incoming_cell(TOR_Payload_V_Padding); // we ignore v padding cells
    this.ready = this.handshake();
}

//makes the tor handshake
TOR_Protocol.prototype.handshake = function () {
    return new Promise(function(resolve,reject){
        //save this handler for exception handlers
        this.reject_handshake_promise = reject;

        //negotiate the tor link version
        var versions = new TOR_Payload_Versions();
        versions.addVersion(3); // currently we support only v3 of the link protocol
        this.set_cell_handler(TOR_Payload_Versions, ((server_versions)=>{
            //find a common version
            var common_versions = versions.supported_versions.filter((v)=>{return server_versions.supported_versions.indexOf(v)>-1});
            console.log("Onion Relay supports link protocol versions: ", server_versions.supported_versions);
            if(common_versions.length === 0)
            {
                throw new TOR_Error(tor_error_handlers.not_supported_versions, "Onion router's link protocol version is not supported");
            }
            var negociated_link_version = Math.max.apply(Math, common_versions);
            console.log("Using link protocol version: ", negociated_link_version);
            this.change_tor_link_version(negociated_link_version);

            //from now on further version cells need to be ignored
            this.ignore_incoming_cell(TOR_Payload_Versions);

            if(this.tor_link_protocol_version >= 3) //v3 handshake is in use
            {
                //now we expect a certs cell
                this.set_cell_handler(TOR_Payload_Certs, (certs)=>{
                    //determine if the router has in fact the secret keys which he claims to have
                    certs.establishIdentity(this.lower_processor.tls_server_certificate);

                    //see if we know the router
                    if(TOR_KnowledgeBase.getInstance().isRouterKnown(certs.identity_fingerprint))
                    {
                        //TODO: verify that the certs match the router descriptor
                    }

                    this.guard_fingerprint = certs.identity_fingerprint;
                    this.guard_certs = certs;

                    //ignore further certs cells
                    this.ignore_incoming_cell(TOR_Payload_Certs);

                    //we are not an OR so we do not authenticate
                    this.ignore_incoming_cell(TOR_Payload_Auth_Challenge);

                    //expect a net info cell
                    this.set_cell_handler(TOR_Payload_Net_Info, (addresses)=>{
                        //ignore further netinfo cell
                        this.ignore_incoming_cell(TOR_Payload_Net_Info);

                        this.addr = addresses.getOtherAddr();
                        console.log("OR says that our ip is:", this.addr);

                        //craft a net info cell
                        var net_info = new TOR_Payload_Net_Info();
                        net_info.setOtherAddr(addresses.getAnyThisAddr());
                        net_info.appendThisAddr(this.addr);

                        //finish the handshake by sending out a net info cell
                        console.log("We are now ready to bootstrap");
                        this.send_out_tor_cell(net_info);

                        //we are now ready to build circuits
                        this.reject_handshake_promise = undefined;
                        resolve();
                    });
                });
            }

        }));

        //initialize the handshake process
        this.send_out_tor_cell(versions);
    }.bind(this));
};

TOR_Protocol.prototype.set_cell_handler = function (obj, fun) {
    this.cell_handlers[obj.prototype.constructor] = fun; //javascript is so funny xD
};

TOR_Protocol.prototype.unset_cell_handler = function (obj) {
    this.set_cell_handler(obj, undefined);
};

//ignores incoming cells
TOR_Protocol.prototype.ignore_incoming_cell = function (obj) {
    this.set_cell_handler(obj, ()=>{});
};

TOR_Protocol.prototype.change_tor_link_version = function (version) {
    this.tor_link_protocol_version = version;
    this.lower_processor.change_tor_link_version(this.tor_link_protocol_version);
};

TOR_Protocol.prototype.process_incoming_data = function (data) {
    try
    {
        var cell = new TOR_Cell(this.tor_link_protocol_version, data);
        var callback = this.cell_handlers[cell.payload.constructor];

        //case 1 - a global circuit handler is present -> applies for padding,version,certs cells...
        if (callback !== undefined)
        {
            callback(cell.payload);
        }
        //case 2 - when circuit_id != 0 and no global callback is present the payload will belong to a circuit
        else if (cell.circuit_id > 0 && this.circuit_router_handlers[cell.circuit_id] !== undefined)
        {
            this.circuit_router_handlers[cell.circuit_id](cell.payload);
        }
        else { //case 3 - unexpected cell - close the connection :P
            throw new TOR_Error(tor_error_handlers.unexpected_cell_type,
                "Unavailable packet handler for command number "+cell.command+" -> "+cell.payload.constructor.toString().match(/function (\w*)/)[1]+" and circuit id "+cell.circuit_id);
        }
    } catch(ex) {
        if(ex instanceof TOR_Error) {
            this.handle_error(ex);
        }else{
            console.log(ex);
        }
        if(this.reject_handshake_promise !== undefined) //reject the handshake promise
        {
            this.reject_handshake_promise();
        }
    }
};

//sends out a tor cell to lower processing layers
//it takes a payload object as an argument and an optional circuit_id
TOR_Protocol.prototype.send_out_tor_cell = function (payload, circuit_id) {
    var cell = new TOR_Cell(this.tor_link_protocol_version);
    cell.setPayload(payload);
    if(circuit_id === undefined)
    {
        cell.circuit_id = 0;
    }
    else
    {
        cell.circuit_id = circuit_id;
    }
    this.lower_processor.send_downstream_fun(cell.dumpBytes());
};

TOR_Protocol.prototype.handle_error = function (ex) {
    console.log("TOR error occured: ", ex.user_message);
    if(ex.handler_name === "close_connection")
    {
        this.lower_processor.destroy();
    }
};

//creates a new circuit on top of the connection
TOR_Protocol.prototype.create_new_circuit = function() {

    console.log("Creating new circuit");

    var random_bytes = "";
    if(this.tor_link_protocol_version <= 3)
    {
        random_bytes = forge.random.getBytesSync(2);
    }
    else
    {
        random_bytes = forge.random.getBytesSync(4);
    }
    var buffer = forge.util.createBuffer();
    buffer.putBytes(random_bytes);
    var new_circuit_id = 0;

    if(this.tor_link_protocol_version <= 3)
    {
        new_circuit_id = buffer.getInt16();
    }
    else
    {
        new_circuit_id = buffer.getInt32();
    }
    buffer.clear();

    var circuit = new TOR_Circuit(this, new_circuit_id, (payload)=>{this.send_out_tor_cell(payload, new_circuit_id)});
    this.circuit_router_handlers[new_circuit_id] = circuit.process_cell_payload.bind(circuit);
    circuit.start();
    return circuit;
};

TOR_Protocol.prototype.tear_down_circuit = function(circuit_id) {
    this.circuit_router_handlers[circuit_id] = undefined;
};
