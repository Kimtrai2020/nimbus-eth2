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


const
  simulationDepositsCount = 128
  outTestDir = "./rest_test_keystore_management"
  outValidatorsDir = "./rest_test_keystore_management/validators"
  outSecretsDir = "./rest_test_keystore_management/secrets"
  outDepositsFile = "./rest_test_keystore_management/deposits.json"

proc runNode =
 # Generate deposits. Todo: Make this function here and in `deposits_contract.nim`
  let
    rng = keys.newRng()
    mnemonic = generateMnemonic(rng[])
    seed = getSeed(mnemonic, KeyStorePass.init "")
    cfg = defaultRuntimeConfig

  let vres = secureCreatePath(string outValidatorsDir)
  if vres.isErr():
    warn "Could not create validators folder",
          path = string outValidatorsDir, err = ioErrorMsg(vres.error)

  let sres = secureCreatePath(string outSecretsDir)
  if sres.isErr():
    warn "Could not create secrets folder",
          path = string outSecretsDir, err = ioErrorMsg(sres.error)

  let deposits = generateDeposits(
    cfg,
    rng[],
    seed,
    0, simulationDepositsCount,
    string outValidatorsDir,
    string outSecretsDir)

  if deposits.isErr:
    fatal "Failed to generate deposits", err = deposits.error
    quit 1

  let launchPadDeposits =
    mapIt(deposits.value, LaunchPadDeposit.init(cfg, it))

  Json.saveFile(string outDepositsFile, launchPadDeposits)
  notice "Deposit data written", filename = outDepositsFile

  # Creating Testnet
  var cmdLineTestBeaconNodeConf: seq[TaintedString]
  cmdLineTestBeaconNodeConf.add "--data-dir=rest_test_keystore_management".TaintedString
  cmdLineTestBeaconNodeConf.add "createTestnet"
  cmdLineTestBeaconNodeConf.add "--total-validators=128".TaintedString
  cmdLineTestBeaconNodeConf.add "--deposits-file=rest_test_keystore_management/deposits.json".TaintedString
  cmdLineTestBeaconNodeConf.add "--output-genesis=rest_test_keystore_management/genesis.ssz".TaintedString
  cmdLineTestBeaconNodeConf.add "--output-bootstrap-file=rest_test_keystore_management/beacon_node.enr".TaintedString
  cmdLineTestBeaconNodeConf.add "--netkey-file=network_key.json".TaintedString
  cmdLineTestBeaconNodeConf.add "--insecure-netkey-password=true".TaintedString
  cmdLineTestBeaconNodeConf.add "--genesis-offset=0".TaintedString


  let testBNconfig = BeaconNodeConf.load(cmdLine = cmdLineTestBeaconNodeConf)
  testBNconfig.doCreateTestnet(rng[])

  var cmdLineBeaconNodeConf: seq[TaintedString]
  cmdLineBeaconNodeConf.add "--tcp-port=49000".TaintedString
  cmdLineBeaconNodeConf.add "--udp-port=49000".TaintedString
  cmdLineBeaconNodeConf.add "--network=rest_test_keystore_management".TaintedString
  cmdLineBeaconNodeConf.add "--data-dir=rest_test_keystore_management".TaintedString
  cmdLineBeaconNodeConf.add "--validators-dir=rest_test_keystore_management/validators".TaintedString
  cmdLineBeaconNodeConf.add "--secrets-dir=rest_test_keystore_management/secrets".TaintedString
  cmdLineBeaconNodeConf.add "--metrics-address=127.0.0.1".TaintedString
  cmdLineBeaconNodeConf.add "--metrics-port=48008".TaintedString
  cmdLineBeaconNodeConf.add "--rest-address=127.0.0.1".TaintedString
  cmdLineBeaconNodeConf.add "--rest-port=47000".TaintedString
  cmdLineBeaconNodeConf.add "--keymanager=true".TaintedString
  cmdLineBeaconNodeConf.add "--keymanager-port=47000".TaintedString
  cmdLineBeaconNodeConf.add "--keymanager-address=127.0.0.1".TaintedString
  cmdLineBeaconNodeConf.add "--doppelganger-detection=off".TaintedString

  let config  = BeaconNodeConf.load(cmdLine = cmdLineBeaconNodeConf)

  let metadata = loadEth2NetworkMetadata(outTestDir)

  echo "before node init"
  let node = BeaconNode.init(
    metadata.cfg,
    rng,
    config,
    metadata.depositContractDeployedAt,
    metadata.eth1Network,
    metadata.genesisData,
    metadata.genesisDepositsSnapshot
  )

  node.start()

runNode()
