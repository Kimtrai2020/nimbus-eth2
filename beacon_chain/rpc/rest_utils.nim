import std/options,
       presto,
       nimcrypto/utils as ncrutils,
       ../spec/[forks],
       ../spec/eth2_apis/[rest_types, eth2_rest_serialization],
       ../beacon_node,
       ../consensus_object_pools/blockchain_dag,
       ./rest_constants

export
  options, eth2_rest_serialization, blockchain_dag, presto, rest_types,
  rest_constants

type
  ValidatorIndexError* {.pure.} = enum
    UnsupportedValue, TooHighValue

func match(data: openarray[char], charset: set[char]): int =
  for ch in data:
    if ch notin charset:
      return 1
  0

proc validate(key: string, value: string): int =
  ## This is rough validation procedure which should be simple and fast,
  ## because it will be used for query routing.
  case key
  of "{epoch}":
    0
  of "{slot}":
    0
  of "{peer_id}":
    0
  of "{state_id}":
    0
  of "{block_id}":
    0
  of "{validator_id}":
    0
  else:
    1

func getCurrentSlot*(node: BeaconNode, slot: Slot):
    Result[Slot, cstring] =
  if slot <= (node.dag.head.slot + (SLOTS_PER_EPOCH * 2)):
    ok(slot)
  else:
    err("Requesting slot too far ahead of the current head")

func getCurrentBlock*(node: BeaconNode, slot: Slot):
    Result[BlockRef, cstring] =
  let bs = node.dag.getBlockBySlot(? node.getCurrentSlot(slot))
  if bs.slot == bs.blck.slot:
    ok(bs.blck)
  else:
    err("Block not found")

proc getCurrentHead*(node: BeaconNode, slot: Slot): Result[BlockRef, cstring] =
  let res = node.dag.head
  # if not(node.isSynced(res)):
  #   return err("Cannot fulfill request until node is synced")
  if res.slot + uint64(2 * SLOTS_PER_EPOCH) < slot:
    return err("Requesting way ahead of the current head")
  ok(res)

proc getCurrentHead*(node: BeaconNode,
                     epoch: Epoch): Result[BlockRef, cstring] =
  if epoch > MaxEpoch:
    return err("Requesting epoch for which slot would overflow")
  node.getCurrentHead(compute_start_slot_at_epoch(epoch))

proc getBlockSlot*(node: BeaconNode,
                   stateIdent: StateIdent): Result[BlockSlot, cstring] =
  case stateIdent.kind
  of StateQueryKind.Slot:
    ok(node.dag.getBlockBySlot(? node.getCurrentSlot(stateIdent.slot)))
  of StateQueryKind.Root:
    if stateIdent.root == getStateRoot(node.dag.headState.data):
      ok(node.dag.headState.blck.atSlot())
    else:
      # We don't have a state root -> BlockSlot mapping
      err("State not found")
  of StateQueryKind.Named:
    case stateIdent.value
    of StateIdentType.Head:
      ok(node.dag.head.atSlot())
    of StateIdentType.Genesis:
      ok(node.dag.genesis.atSlot())
    of StateIdentType.Finalized:
      ok(node.dag.finalizedHead)
    of StateIdentType.Justified:
      ok(node.dag.head.atEpochStart(getStateField(
        node.dag.headState.data, current_justified_checkpoint).epoch))

proc getBlockRef*(node: BeaconNode,
                   id: BlockIdent): Result[BlockRef, cstring] =
  case id.kind
  of BlockQueryKind.Named:
    case id.value
    of BlockIdentType.Head:
      ok(node.dag.head)
    of BlockIdentType.Genesis:
      ok(node.dag.genesis)
    of BlockIdentType.Finalized:
      ok(node.dag.finalizedHead.blck)
  of BlockQueryKind.Root:
    let res = node.dag.getRef(id.root)
    if isNil(res):
      err("Block not found")
    else:
      ok(res)
  of BlockQueryKind.Slot:
    node.getCurrentBlock(id.slot)

proc getBlockDataFromBlockIdent*(node: BeaconNode,
                                 id: BlockIdent): Result[BlockData, cstring] =
  ok(node.dag.get(? node.getBlockRef(id)))

template withStateForBlockSlot*(node: BeaconNode,
                                blockSlot: BlockSlot, body: untyped): untyped =
  template isState(state: StateData): bool =
    state.blck.atSlot(getStateField(state.data, slot)) == blockSlot

  if isState(node.dag.headState):
    withStateVars(node.dag.headState):
      var cache {.inject, used.}: StateCache
      body
  else:
    let rpcState = assignClone(node.dag.headState)
    node.dag.withUpdatedState(rpcState[], blockSlot) do:
      body
    do:
      discard # Fall-through - rest handlers do their own thing here

proc toValidatorIndex*(value: RestValidatorIndex): Result[ValidatorIndex,
                                                          ValidatorIndexError] =
  when sizeof(ValidatorIndex) == 4:
    if uint64(value) < VALIDATOR_REGISTRY_LIMIT:
      # On x86 platform Nim allows only `int32` indexes, so all the indexes in
      # range `2^31 <= x < 2^32` are not supported.
      if uint64(value) <= uint64(high(int32)):
        ok(ValidatorIndex(value))
      else:
        err(ValidatorIndexError.UnsupportedValue)
    else:
      err(ValidatorIndexError.TooHighValue)
  elif sizeof(ValidatorIndex) == 8:
    if uint64(value) < VALIDATOR_REGISTRY_LIMIT:
      ok(ValidatorIndex(value))
    else:
      err(ValidatorIndexError.TooHighValue)
  else:
    doAssert(false, "ValidatorIndex type size is incorrect")

func syncCommitteeParticipants*(forkedState: ForkedHashedBeaconState,
                                epoch: Epoch
                               ): Result[seq[ValidatorPubKey], cstring] =
  withState(forkedState):
    when stateFork >= BeaconStateFork.Altair:
      let
        epochPeriod = sync_committee_period(epoch)
        curPeriod = sync_committee_period(state.data.slot)
      if epochPeriod == curPeriod:
        ok(@(state.data.current_sync_committee.pubkeys.data))
      elif epochPeriod == curPeriod + 1:
        ok(@(state.data.next_sync_committee.pubkeys.data))
      else:
        err("Epoch is outside the sync committee period of the state")
    else:
      err("State's fork do not support sync committees")

func keysToIndices*(cacheTable: var Table[ValidatorPubKey, ValidatorIndex],
                    forkedState: ForkedHashedBeaconState,
                    keys: openArray[ValidatorPubKey]
                   ): seq[Option[ValidatorIndex]] =
  var indices = newSeq[Option[ValidatorIndex]](len(keys))
  var keyset =
    block:
      var res: Table[ValidatorPubKey, int]
      for inputIndex, pubkey in keys.pairs():
        # Try to search in cache first.
        cacheTable.withValue(pubkey, vindex):
          indices[inputIndex] = some(vindex[])
        do:
          res[pubkey] = inputIndex
      res
  if len(keyset) > 0:
    for validatorIndex, validator in getStateField(forkedState,
                                                   validators).pairs():
      keyset.withValue(validator.pubkey, listIndex):
        # Store pair (pubkey, index) into cache table.
        cacheTable[validator.pubkey] = ValidatorIndex(validatorIndex)
        # Fill result sequence.
        indices[listIndex[]] = some(ValidatorIndex(validatorIndex))
  indices

proc getRouter*(): RestRouter =
  RestRouter.init(validate)
