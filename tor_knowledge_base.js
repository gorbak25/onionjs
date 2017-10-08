/*
Create a global interface for saving the current tor network status
 */

//for details see section 2.1.1 of dir-spec.txt
//represents an onion router descripto
function TOR_Relay_Descriptor(){
    this.nickname = undefined;
    this.address = undefined;
    this.or_port = undefined;
    this.socks_port = undefined;
    this.dir_port = undefined;

    this.identity_ed25519 = undefined;
    this.master_key_ed25519 = undefined;

    this.bandwidth_avg = undefined;
    this.bandwidth_burst = undefined;
    this.bandwidth_observed = undefined;

    this.platform = undefined;
    this.published = undefined;
    this.fingerprint = undefined;
    this.hibernating = undefined;
    this.uptime = undefined;

    this.onion_key = undefined;
    this.onion_key_crosscert = undefined;

    this.ntor_onion_key = undefined;
    this.ntor_onion_key_crosscert = undefined;

    this.signing_key = undefined;

    this.accept = undefined;
    this.reject = undefined;
    this.ipv6_policy = undefined;

    this.router_sig_ed25519 = undefined;

    this.router_signature = undefined;

    this.contact = undefined;

    this.family = undefined;

    this.read_history = undefined;
    this.write_history = undefined;

    this.eventdns = undefined;

    this.caches_extra_info = undefined;
    this.extra_info_digest = undefined;
    this.hidden_service_dir = undefined;
    this.protocols = undefined; //obsolete
    this.allow_single_hop_exits = undefined; //obsolete
    this.or_address = []; //additional addresses
    this.tunnelled_dir_server = undefined;
    this.proto = undefined;
}

//stores the basic info about a given OR from the current consensus
//see section 3.4.1 of dir-spec.txt
function TOR_Relay_BasicInfo(){
    this.nickname = undefined;
    this.descriptor_digest = undefined;
    this.publication_date = undefined;
    this.address = undefined;
    this.or_port = undefined;
    this.dir_port = undefined;

    this.tor_flags = undefined;
    this.tor_version = undefined;
    this.tor_proto = undefined;
    this.bandwidth = undefined;
    this.policy = undefined;
}

//The knowledge base represents the tor network status
//as presented in the current consensus
function TOR_KnowledgeBase_Obj(){
    //descriptor digest -> descriptor object
    this.descriptors = {};
    //identity_digest -> TOR_Relay_BasicInfo
    this.routers = {};

    this.valid_after = undefined; //date after the current consensus will be valid
    this.fresh_until = undefined; //date after we must start thinking about fetching a new consensus
    this.valid_until = undefined; //date after the current consensus becomes invalid
}

//returns if we have basic info for the given router
TOR_KnowledgeBase_Obj.prototype.isRouterKnown = function(identity){
    return this.routers[identity] !== undefined;
};

//retrieves basic info for a given identity
TOR_KnowledgeBase_Obj.prototype.getBasicInfoFor = function (identity) {
    return this.routers[identity];
};

//returns if we have a descriptor for a given identity
TOR_KnowledgeBase_Obj.prototype.doWeHaveADescriptorFor = function(identity){
    if(this.isRouterKnown(identity))
    {
        var basic_info = this.getBasicInfoFor(identity);
        if(basic_info.descriptor_digest !== undefined)
        {
            var descriptor = this.descriptors[basic_info.descriptor_digest];
            return descriptor !== undefined;
        }
    }
    return false;
};

//retrieves a descriptor for a given identity
TOR_KnowledgeBase_Obj.prototype.getDescriptorFor = function (identity){
    return this.descriptors[this.getBasicInfoFor(identity).descriptor_digest];
};

//a singleoton for storing the current knowledge base
var TOR_KnowledgeBase = (function () {
    var instance;

    function createInstance() {
        var object = new TOR_KnowledgeBase_Obj();
        return object;
    }

    return {
        getInstance: function () {
            if (!instance) {
                instance = createInstance();
            }
            return instance;
        }
    };
})();

