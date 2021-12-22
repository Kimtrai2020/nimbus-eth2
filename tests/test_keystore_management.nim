{.used.}

import
  std/[os, options, json, typetraits],
  unittest2, chronos, chronicles, stint, json_serialization,
  blscurve, eth/keys, nimcrypto/utils,
  libp2p/crypto/crypto as lcrypto,
  stew/[io2, byteutils],
  ../beacon_chain/filepath,
  ../beacon_chain/networking/network_metadata,
  ../beacon_chain/spec/eth2_merkleization,
  ../beacon_chain/spec/datatypes/base,
  ../beacon_chain/spec/[crypto, keystore],
  ../beacon_chain/validators/keystore_management,
  ./testutil

const
  simulationDepositsCount = 2
  outTestDir = "./test_keystore_management"
  outValidatorsDir = "./test_keystore_management/validators"
  outSecretsDir = "./test_keystore_management/secrets"

proc directoryItemsCount(dir: string):int {.raises: [OSError].} =
  for el in walkDir(dir):
    result += 1

proc emptyDir(dir: string): bool =
  dir.directoryItemsCount == 0

proc listValidatorHashesFormDir(dir: string): seq[string] =
  for kind, file in walkDir(dir):
    if kind == pcDir:
      result.add(splitFile(file).name)

proc checkExistence(validatorHash, dir: string): bool =
  for kind, file in walkDir(dir):
    if splitFile(file).name  == validatorHash:
      return true
  return false

proc checkContent(filePath, expectedContent: string): bool =
  var file: File

  discard open(file, filePath)
  let content: string = readAll(file)
  close(file)
  return expectedContent == content

let
  rng = keys.newRng()
  mnemonic = generateMnemonic(rng[])
  seed = getSeed(mnemonic, KeyStorePass.init "")
  cfg = defaultRuntimeConfig
  vres = secureCreatePath(outValidatorsDir)

if vres.isErr():
  warn "Could not create validators folder",
        path = outValidatorsDir, err = ioErrorMsg(vres.error)

let sres = secureCreatePath(outSecretsDir)
if sres.isErr():
  warn "Could not create secrets folder",
        path = outSecretsDir, err = ioErrorMsg(sres.error)

let deposits = generateDeposits(
  cfg,
  rng[],
  seed,
  0, simulationDepositsCount,
  outValidatorsDir,
  outSecretsDir)

if deposits.isErr:
  fatal "Failed to generate deposits", err = deposits.error
  quit 1

let validatorPubKeys = listValidatorHashesFormDir(outValidatorsDir)

suite "removeValidatorFiles" & preset():
  test "Remove validator files" & preset():
    var
      validatorsCountBefore: int
      validatorsCountAfter: int
      secretsCountBefore: int
      secretsCountAfter: int

    validatorsCountBefore = directoryItemsCount(outValidatorsDir)
    secretsCountBefore = directoryItemsCount(outSecretsDir)

    let firstValidator = validatorPubKeys[0]
    var res = removeValidatorFiles(outValidatorsDir, outSecretsDir, firstValidator)

    validatorsCountAfter = directoryItemsCount(outValidatorsDir)
    secretsCountAfter = directoryItemsCount(outSecretsDir)

    check(res.value() == RemoveValidatorStatus.deleted)

    check(validatorsCountBefore - 1 == validatorsCountAfter)
    check(not (fileExists(outValidatorsDir / firstValidator / KeystoreFileName)))
    check(not (checkExistence(firstValidator, outValidatorsDir)))

    check(secretsCountBefore - 1 == secretsCountAfter)
    check(not (checkExistence(firstValidator, outSecretsDir)))

  test "Remove nonexistent validator" & preset():
    let nonexistentValidator = "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    var res = removeValidatorFiles(outValidatorsDir, outSecretsDir, nonexistentValidator)

    check(res.value() == RemoveValidatorStatus.missingDir)

  test "Remove validator files twice" & preset():
    let secondValidator = validatorPubKeys[1]

    var res1 = removeValidatorFiles(outValidatorsDir, outSecretsDir, secondValidator)
    var res2 = removeValidatorFiles(outValidatorsDir, outSecretsDir, secondValidator)

    check(not (checkExistence(secondValidator, outValidatorsDir)))
    check(not (checkExistence(secondValidator, outSecretsDir)))
    check(res1.value() == RemoveValidatorStatus.deleted)
    check(res2.value() == RemoveValidatorStatus.missingDir)

  os.removeDir(outValidatorsDir)
  os.removeDir(outSecretsDir)

suite "createValidatorFiles" & preset():
  setup:
    const
      password = string.fromBytes hexToSeqByte("7465737470617373776f7264f09f9491")
      secretBytes = hexToSeqByte "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
      secretNetBytes = hexToSeqByte "08021220fe442379443d6e2d7d75d3a58f96fbb35f0a9c7217796825fc9040e3b89c5736"
      salt = hexToSeqByte "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
      iv = hexToSeqByte "264daa3f303d7259501c93d997d84fe6"

    let
      secret = ValidatorPrivKey.fromRaw(secretBytes).get

      keystore = createKeystore(kdfPbkdf2, rng[], secret,
                                KeystorePass.init password,
                                salt=salt, iv=iv,
                                description = "This is a test keystore that uses PBKDF2 to secure the secret.",
                                path = validateKeyPath("m/12381/60/0/0").expect("Valid Keypath"))

    var encodedStorage = Json.encode(keystore)

    let
      keyHash =  "0x" & keystore.pubkey.toHex()
      keystoreDir = outValidatorsDir / keyHash
      secretFile = outSecretsDir / keyHash
      keystoreFile = outValidatorsDir / keyHash / KeystoreFileName

  test "Add keystore files" & preset():
    let
      res = createValidatorFiles(outSecretsDir, outValidatorsDir,
                                 keystoreDir,
                                 secretFile, password,
                                 keystoreFile, encodedStorage)

      validatorsCount = directoryItemsCount(outValidatorsDir)
      secretsCount = directoryItemsCount(outSecretsDir)

      validatorPubKeys = listValidatorHashesFormDir(outValidatorsDir)
      newValidatorHash = validatorPubKeys[0]

    check(validatorsCount == 1)
    check(secretsCount == 1)

    check(checkExistence(newValidatorHash, outValidatorsDir))
    check(checkExistence(newValidatorHash, outSecretsDir))

    check(checkContent(secretFile, password))
    check(checkContent(keystoreFile, encodedStorage))

    os.removeDir(outValidatorsDir)
    os.removeDir(outSecretsDir)

  test "Add keystore files twice" & preset():
    let
      res1 = createValidatorFiles(outSecretsDir, outValidatorsDir,
                                  keystoreDir,
                                  secretFile, password,
                                  keystoreFile, encodedStorage)

      res2 = createValidatorFiles(outSecretsDir, outValidatorsDir,
                                  keystoreDir,
                                  secretFile, password,
                                  keystoreFile, encodedStorage)

      validatorsCount = directoryItemsCount(outValidatorsDir)
      secretsCount = directoryItemsCount(outSecretsDir)
      validatorPubKeys = listValidatorHashesFormDir(outValidatorsDir)
      newValidatorHash = validatorPubKeys[0]

    check(validatorsCount == 1)
    check(secretsCount == 1)

    check(checkExistence(newValidatorHash, outValidatorsDir))
    check(checkExistence(newValidatorHash, outSecretsDir))
    check(checkContent(secretFile, password))
    check(checkContent(keystoreFile, encodedStorage))

    os.removeDir(outValidatorsDir)
    os.removeDir(outSecretsDir)

  test "`createValidatorFiles` with `secretsDir` without permissions" & preset():
    let
      # Creating `secrets` dir with `UserRead` permissions before calling `createValidatorFiles`
      # which will result in problem with creating `secretFile` inside the dir
      secretsDirNoPermissions = createPath(outSecretsDir, 0o400)
      res = createValidatorFiles(outSecretsDir, outValidatorsDir,
                                 keystoreDir,
                                 secretFile, password,
                                 keystoreFile, encodedStorage)

    # Asserting `createValidatorFiles` will result in
    # error of type `FailedToCreateSecretFile` which will trigger rollback files removal
    check(res.error().kind == FailedToCreateSecretFile)

    # Asserting `secrets` dir will not be removed,
    # but every newly created files will be removed
    check(checkExistence("secrets", outTestDir))
    check(not checkExistence("validators", outTestDir))
    check(emptyDir(outValidatorsDir))
    check(emptyDir(outSecretsDir))

    os.removeDir(outValidatorsDir)
    os.removeDir(outSecretsDir)

  test "`createValidatorFiles` with `validatorsDir` without permissions" & preset():
    let
      # Creating `validators` dir with `UserRead` permissions before calling `createValidatorFiles`
      # which will result in problem with creating `keystoreDir` inside the dir
      validatorsDirNoPermissions = createPath(outValidatorsDir, 0o400)
      res = createValidatorFiles(outSecretsDir, outValidatorsDir,
                                 keystoreDir,
                                 secretFile, password,
                                 keystoreFile, encodedStorage)

    # Asserting `createValidatorFiles` will result in
    # error of type `FailedToCreateKeystoreDir` which will trigger rollback files removal
    check(res.error().kind == FailedToCreateKeystoreDir)

    # Asserting `validators` dir will not be removed,
    # but every newly created files will be removed
    check(not checkExistence("secrets", outTestDir))
    check(checkExistence("validators", outTestDir))
    check(emptyDir(outValidatorsDir))
    check(emptyDir(outSecretsDir))

    os.removeDir(outValidatorsDir)
    os.removeDir(outSecretsDir)

  test "`createValidatorFiles` with `keystoreDir` without permissions" & preset():
    let
      # Creating `keystore` dir with `UserRead` permissions before calling `createValidatorFiles`
      # which will result in problem with creating `keystoreFile` inside this dir
      validatorsDir = createPath(outValidatorsDir, 0o700)
      keystoreDirNoPermissions = createPath(keystoreDir, 0o400)
      res = createValidatorFiles(outSecretsDir, outValidatorsDir,
                                 keystoreDir,
                                 secretFile, password,
                                 keystoreFile, encodedStorage)

    # Asserting `createValidatorFiles` will result in
    # error of type `FailedToCreateKeystoreFile` which will trigger rollback files removal
    check(res.error().kind == FailedToCreateKeystoreFile)

    # Asserting `validators` dir will not be removed,
    # but `keystoreDir` & every newly created files will be removed
    check(not checkExistence(keyHash, outValidatorsDir))
    check(not checkExistence("secrets", outTestDir))
    check(checkExistence("validators", outTestDir))
    check(emptyDir(outValidatorsDir))
    check(emptyDir(outSecretsDir))

    os.removeDir(outValidatorsDir)
    os.removeDir(outSecretsDir)

  test "`createValidatorFiles` with already existing dirs and any error" & preset():

    let
      # Generate deposits so we have files and dirs already existing
      # before testing `createValidatorFiles` failure
      deposits = generateDeposits(
        cfg,
        rng[],
        seed,
        0, simulationDepositsCount,
        outValidatorsDir,
        outSecretsDir)

      validatorsCountBefore = directoryItemsCount(outValidatorsDir)
      secretsCountBefore = directoryItemsCount(outSecretsDir)

      # Creating `keystore` dir with `UserRead` permissions before calling `createValidatorFiles`
      # which will result in error
      keystoreDirNoPermissions = createPath(keystoreDir, 0o400)

      res = createValidatorFiles(outSecretsDir, outValidatorsDir,
                                 keystoreDir,
                                 secretFile, password,
                                 keystoreFile, encodedStorage)

      validatorsCountAfter = directoryItemsCount(outValidatorsDir)
      secretsCountAfter = directoryItemsCount(outSecretsDir)

    check(res.isErr())
    # Asserting `secrets` & `validators` dirs will not be removed during rollback files removal
    check(checkExistence("secrets", outTestDir))
    check(checkExistence("validators", outTestDir))

    # Asserting count of dirs will not change after `createValidatorFiles` failure
    check(validatorsCountBefore == validatorsCountAfter)
    check(secretsCountBefore == secretsCountAfter)

    os.removeDir(outValidatorsDir)
    os.removeDir(outSecretsDir)

os.removeDir("./test_keystore_management")
