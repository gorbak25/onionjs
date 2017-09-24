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

function TOR_Payload_Padding(cell_bytes){

}

function TOR_Payload_Create(cell_bytes){

}

function TOR_Payload_Created(cell_bytes){

}

function TOR_Payload_Relay(cell_bytes){

}

function TOR_Payload_Destroy(cell_bytes){

}

function TOR_Payload_Create_Fast(cell_bytes){

}

function TOR_Payload_Created_Fast(cell_bytes){

}

function TOR_Payload_Versions(cell_bytes) {

}

function TOR_Payload_Net_Info(cell_bytes){

}

function TOR_Payload_Relay_Early(cell_bytes){

}

function TOR_Payload_Create2(cell_bytes) {

}

function TOR_Payload_Created2(cell_bytes) {

}

function TOR_Payload_Padding_Negotiate(cell_bytes) {

}

function TOR_Payload_V_Padding(cell_bytes) {

}

function TOR_Payload_Certs(cell_bytes) {

}

function TOR_Payload_Auth_Challenge(cell_bytes) {

}

function TOR_Payload_Authenticate(cell_bytes) {

}

function TOR_Payload_Authorize(cell_bytes) {

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

//loads a tor cell from bytes
TOR_Cell.prototype.loadBytes = function(cell_bytes){
    var buffer = forge.util.createBuffer();
    buffer.putBytes(cell_bytes);

    this.circuit_id = buffer.getInt(this.circ_id_len*8);
    this.command = buffer.getByte();

    this.payload = new cell_payload_processors[this.command](buffer.getBytes());
};

//dumps a tor cell together with appropriate padding
TOR_Cell.prototype.dumpBytes = function(){
    var payload = this.payload.dumpBytes(); //payload processor will need to handle padding

    var buffer = forge.util.createBuffer();
    buffer.putInt(this.circuit_id, this.circ_id_len*8);
    buffer.putByte(this.command);

    if(this.command === 7 || this.command >= 128)
    {
        buffer.putInt16(payload.length);
    }

    buffer.putBytes(payload);

    return buffer.getBytes();
};

function TOR_Protocol(tor_connection)
{
    this.states = {"UNITIALIZED":"1", "HANDSHAKE_DONE":"2"};
    this.cur_state = this.states["UNITIALIZED"];



    this.cell_types =

    //This array will contain the behavior of the engine upon receiving a given cell type
    this.cell_handlers = {};
    for(var state in this.states)
    {
        this.cell_handlers[this.states[state]] = {};
    }
    this.cell_handlers[this.states["UNITIALIZED"]][]




}

