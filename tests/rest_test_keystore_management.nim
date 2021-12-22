{.used.}

import
  std/httpclient,
  os, options, json, sequtils,
  chronos, chronicles, stint, json_serialization,
  ../beacon_chain/filepath,
  ../beacon_chain/networking/network_metadata,
  eth/keys,
  stew/io2,
  ../beacon_chain/spec/eth2_merkleization,
  ../beacon_chain/spec/datatypes/base,
  ../beacon_chain/validators/keystore_management,
  ../beacon_chain/spec/[crypto, keystore],
  ../beacon_chain/conf,
  ../beacon_chain/beacon_node,
  ../beacon_chain/nimbus_beacon_node,
  ../beacon_chain/rpc/rest_key_management_api,
  ../beacon_chain/spec/eth2_apis/rest_beacon_client,

  ../ncli/resttest,

  ../vendor/nim-stew/stew/shims/net,
  ../vendor/nim-confutils/confutils,
  ../vendor/nimbus-build-system/vendor/Nim/lib/pure/uri,

  std/[json, typetraits],
  unittest2,
  stew/byteutils, blscurve, eth/keys, json_serialization,
  libp2p/crypto/crypto as lcrypto,
  nimcrypto/utils as ncrutils,
# Test utilies
  ./testutil


type
  Config = object
    serverIpAddress {.
      defaultValue: ValidIpAddress.init("127.0.0.1")
      defaultValueDesc: "127.0.0.1"
      desc: "IP address of the beacon node's REST server"
      abbr: "a"
      name: "address" .}: ValidIpAddress
    serverPort {.
      defaultValue: 47000
      desc: "Listening port of the beacon node's REST server"
      abbr: "p"
      name: "port" .}: Port

let config = Config.load
let serverAddress = initTAddress(config.serverIpAddress, config.serverPort)
var client = RestClientRef.new(serverAddress)

# let stateIdent = StateIdent(kind: StateQueryKind.Slot, slot: 0.Slot)
let future = client.getKeys()
let response = waitFor future
echo string.fromBytes(response.data)
let response2 = ContentBody(contentType: response.contentType,
                            data: response.data)
let res = decodeBody(GetKeystoresResponse, response2)
echo res
