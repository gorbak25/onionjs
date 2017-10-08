/*
Interface for creating TOR circuits
Multiple hop circuits are created by chaining the functions :D just like in an onion xD
Circuits expose a data stream which can be chained with a given protocol implementation
*/

//an non optimal wrapper for the sha1 function from forge
function H(bytes) {
    var md = forge.md.sha1.create();
    md.update(bytes);
    return md.digest();
}

//the legacy KDF_TOR key derivation function - needed for the create_fast cells :P
function KDF_TOR(K0)
{
    var K = forge.util.createBuffer();
    var i = 0;
    while (K.length() < KEY_LEN * 2 + HASH_LEN * 3) {
        K.putBuffer(H(K0 + String.fromCharCode(i)));
        i += 1;
    }

    var KH = K.getBytes(HASH_LEN);
    var Df = K.getBytes(HASH_LEN);
    var Db = K.getBytes(HASH_LEN);
    var Kf = K.getBytes(KEY_LEN);
    var Kb = K.getBytes(KEY_LEN);

    return {
      KH: KH,
      Df: Df,
      Db: Db,
      Kf: Kf,
      Kb: Kb
    };
}

//represents a single hop in the circuit, including the guard node
//this is an wrapper to take care of the encryption/decryption of cell payloads and storing of the needed cryptographic keys
//it processes relay cells and extend cells
//it is used to send commands along the circuit
//lower processor is either an TOR_Circuit or another TOR_Onion_Layer
function TOR_Onion_Layer(lower_processor)
{
    this.lower_processor = lower_processor;
    this.identity_fingerprint = undefined; //the identity fingerprint of the router

    //------ CRYPTOGRAPHIC KEYS --------
    this.Df = undefined; //forward integrity check
    this.Db = undefined; //backwards integrity check
    this.Kf = undefined; //forward AES key
    this.Kb = undefined; //backwards AES key
    //----------------------------------
}

//sets a callback for the decrypted cell data
TOR_Onion_Layer.prototype.set_on_pass_upstream_fun = function()
{

};

//processes a relay cell
TOR_Onion_Layer.prototype.process_cell = function (cell) {

};

//sends out a tor relay cell to lower processing layers
TOR_Onion_Layer.prototype.send_out_relay_cell = function(payload)
{
    //TODO: NIY
    //TODO: encryption of the data
    this.lower_processor.send_out_tor_cell(encrypted);
};

//a wrapper class which represents a tor circuit on top of an established tor protocol connection
//the purpose of this wrapper is to correctly handle RELAY_EARLY cells and to take care of onioning and de-onioning of relay cells :D
function TOR_Circuit(tor_connection, circuit_id, send_out_cell_fun)
{
    this.cell_handlers = {};
    this.send_out_tor_cell = send_out_cell_fun;
    this.tor_connection = tor_connection;
    this.circuit_id = circuit_id;
    this.circuit_hops = [];

    this.relay_early_send_count = 0;
    this.early_relay_phase = true;

    //setup the relay_early handler
    this.set_cell_handler(TOR_Payload_Relay_Early, (cell)=>{this.handle_relay_early(cell);});
}

//establishes a new circuit with the guard node and then creates a TOR_Onion_Layer for the guard node
TOR_Circuit.prototype.start = function()
{
    //determine what type of create cells will be used
    //if we start from the ground up we do not have enough information for a proper TAP or NTOR handshake
    if(!TOR_KnowledgeBase.getInstance().doWeHaveADescriptorFor(this.tor_connection.guard_fingerprint)) //no descriptor
    {
        this.ready = this.start_circuit_fast(this.tor_connection.guard_fingerprint);
    }
    else if(TOR_KnowledgeBase.getInstance().getDescriptorFor(this.tor_connection.guard_fingerprint).ntor_onion_key !== undefined) //we have enough information for an ntor handshake
    {
        this.ready = this.start_circuit_NTOR(this.tor_connection.guard_fingerprint);
    }
    else
    {
        this.ready = this.start_circuit_TAP(this.tor_connection.guard_fingerprint);
    }
};

//creates a circuit without using public key cryptography - only applicable when we do not know the descriptor of the OR
TOR_Circuit.prototype.start_circuit_fast = function(identity)
{
    return new Promise(
      function(resolve, reject){
          this.tor_connection.reject_handshake_promise = reject;

          //generate a create_fast cell
          //the secret is generated inside the cell
          var create_fast_cell = new TOR_Payload_Create_Fast();

          //await for a created fast cell
          this.set_cell_handler(TOR_Payload_Created_Fast,(created_fast_cell)=> {
              //derive the encryption keys
              var X = create_fast_cell.key_material;
              var Y = created_fast_cell.key_material;
              var K0 = X + Y;
              var crypto_keys = KDF_TOR(K0);

              //check if the server has generated the same keys as we
              if(crypto_keys.KH !== created_fast_cell.derivative_key_material)
              {
                  throw new TOR_Error(tor_error_handlers.circuit_creation_failure, "Failed to establish common keys for circuit");
              }

              //create an onion_layer using the common keys
              this.addHop(identity, crypto_keys);

              //if we succeeded the circuit was created
              this.ignore_incoming_cell(TOR_Payload_Created_Fast);
              this.tor_connection.reject_handshake_promise = undefined;
              resolve();
          });

          //send out the create fast cell
          this.send_out_tor_cell(create_fast_cell);

      }.bind(this));
};

//creates a circuit using the old legacy TAP handshake using CREATE cells
//it is used when we know the OR descriptor and we do not have a curve25519 public key
TOR_Circuit.prototype.start_circuit_TAP = function(identity)
{
//NIY
};

//creates a circuit using the NTOR handshake using CREATE2 cells
//it is used when we have full knowledge about a given OR
TOR_Circuit.prototype.start_circuit_NTOR = function(identity)
{
//NIY
};

TOR_Circuit.prototype.getLastHop = function()
{
    return this.circuit_hops[this.circuit_hops-1];
};

//after establishing cryptographic keys adds an onion layer to the circuit
TOR_Circuit.prototype.addHop = function(identity, crypto_keys)
{
    if(this.circuit_hops.length === 0) //the first layer of the circuit
    {
        //create the wrapper
        var layer = new TOR_Onion_Layer(this);
        layer.identity_fingerprint = identity;
        layer.Db = crypto_keys.Db;
        layer.Df = crypto_keys.Df;
        layer.Kb = crypto_keys.Kb;
        layer.Kf = crypto_keys.Kf;

        this.set_cell_handler(TOR_Payload_Relay, layer.process_cell.bind(layer));

        //now just save the wrapper for convenience
        this.circuit_hops[this.circuit_hops.length] = layer;
    }
    else
    {
        var layer = new TOR_Onion_Layer(this.getLastHop());
        layer.identity_fingerprint = identity;
        layer.Db = crypto_keys.Db;
        layer.Df = crypto_keys.Df;
        layer.Kb = crypto_keys.Kb;
        layer.Kf = crypto_keys.Kf;

        this.getLastHop().set_on_pass_upstream_fun(layer.process_cell.bind(layer));
        this.circuit_hops[this.circuit_hops.length] = layer;
    }
};

//convert a relay early cell to a relay cell
TOR_Circuit.prototype.handle_relay_early = function(cell)
{
    this.process_cell_payload(cell.getRelayCell());
};

//processes cells designated for the circuit and not affecting the global protocol state
TOR_Circuit.prototype.process_cell_payload = function(payload)
{
    var callback = this.cell_handlers[payload.constructor];
    if(callback !== undefined)
    {
        callback(payload);
    }
    else{
        throw new TOR_Error(tor_error_handlers.unexpected_cell_type, "Unexpected cell inside circuit");
    }
};

//sends out a relay cell and if needed changes a relay cell into a relay early cell
TOR_Circuit.prototype.send_out_relay_cell = function(cell)
{
    if(this.early_relay_phase) //the first 7-8 cells need to be relay early cells
    {
        var encapsulation = new TOR_Payload_Relay_Early();
        encapsulation.encapsulateRelayCell(cell);
        this.relay_early_send_count += 1;
        if(this.relay_early_send_count > 7)
        {
            this.early_relay_phase = false; //stop using relay early cells and switch to relay cells
        }
        this.send_out_tor_cell(encapsulation);
    }
    else
    {
        this.send_out_tor_cell(cell);
    }
};

TOR_Circuit.prototype.set_cell_handler = function (obj, fun) {
    this.cell_handlers[obj.prototype.constructor] = fun; //javascript is so funny xD
};

TOR_Circuit.prototype.unset_cell_handler = function (obj) {
    this.set_cell_handler(obj, undefined);
};

//ignores incoming cells
TOR_Circuit.prototype.ignore_incoming_cell = function (obj) {
    this.set_cell_handler(obj, ()=>{});
};
