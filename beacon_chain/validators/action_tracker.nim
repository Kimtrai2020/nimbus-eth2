import
  std/[tables, sequtils],
  bearssl,
  stew/shims/[sets, hashes], chronicles,
  eth/p2p/discoveryv5/random2,
  ../spec/datatypes/base,
  ../spec/[helpers, network],
  ../consensus_object_pools/[block_pools_types, spec_cache]

export base, helpers, network, sets, tables

const
  SUBNET_SUBSCRIPTION_LEAD_TIME_SLOTS* = 4 ##\
    ## The number of slots before we're up for aggregation duty that we'll
    ## actually subscribe to the subnet we're aggregating for - this gives
    ## the node time to find a mesh etc - can likely be further trimmed
  KNOWN_VALIDATOR_DECAY = 3 * 32 * SLOTS_PER_EPOCH ##\
    ## The number of slots before we "forget" about validators that have
    ## registered for duties - once we've forgotten about a validator, we'll
    ## eventually decrease the number of stability subnets we're subscribed to -
    ## 3 epochs because we perform attestations once every epoch, +1 to deal
    ## with rounding + 1 to deal with the network growing beyond 260k validators
    ## and us not validating every epoch any more.
    ## When known validators decrease, we will keep the stability subnet around
    ## until it "naturally" expires.

type
  AggregatorDuty* = object
    subnet_id*: SubnetId
    slot*: Slot

  ActionTracker* = object
    rng: ref BrHmacDrbgContext

    subscribeAllSubnets*: bool

    currentSlot*: Slot ##\
      ## Duties that we accept are limited to a range around the current slot

    subscribedSubnets*: AttnetBits ##\
      ## All subnets we're currently subscribed to

    stabilitySubnets: seq[tuple[subnet_id: SubnetId, expiration: Epoch]] ##\
      ## The subnets on which we listen and broadcast gossip traffic to maintain
      ## the health of the network - these are advertised in the ENR
    nextCycleEpoch*: Epoch

    # Used to track the next attestation and proposal slots using an
    # epoch-relative coordinate system. Doesn't need initialization.
    attestingSlots*: array[2, uint32]
    proposingSlots*: array[2, uint32]
    lastCalculatedEpoch*: Epoch

    knownValidators*: Table[ValidatorIndex, Slot] ##\
      ## Validators that we've recently seen - we'll subscribe to one stability
      ## subnet for each such validator - the slot is used to expire validators
      ## that no longer are posting duties

    duties*: HashSet[AggregatorDuty] ##\
      ## Known aggregation duties in the near future - before each such
      ## duty, we'll subscribe to the corresponding subnet to collect
      ## attestations for the aggregate

func hash*(x: AggregatorDuty): Hash =
  hashAllFields(x)

# https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/phase0/validator.md#phase-0-attestation-subnet-stability
func randomStabilitySubnet*(
    self: ActionTracker, epoch: Epoch): tuple[subnet_id: SubnetId, expiration: Epoch] =
  (
    self.rng[].rand(ATTESTATION_SUBNET_COUNT - 1).SubnetId,
    epoch + EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION +
      self.rng[].rand(EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION.int).uint64,
  )

proc registerDuty*(
    tracker: var ActionTracker, slot: Slot, subnet_id: SubnetId,
    vidx: ValidatorIndex, isAggregator: bool) =
  # Only register relevant duties
  if slot < tracker.currentSlot or
      slot + (SLOTS_PER_EPOCH * 2) <= tracker.currentSlot:
    debug "Irrelevant duty", slot, subnet_id, vidx
    return

  tracker.knownValidators[vidx] = slot # Update validator last-seen registry

  if isAggregator:
    let newDuty = AggregatorDuty(slot: slot, subnet_id: subnet_id)

    if newDuty in tracker.duties:
      return

    debug "Registering aggregation duty", slot, subnet_id, vidx
    tracker.duties.incl(newDuty)

const allSubnetBits = block:
  var res: AttnetBits
  for i in 0..<res.len: res[i] = true
  res

func aggregateSubnets*(tracker: ActionTracker, wallSlot: Slot): AttnetBits =
  var res: AttnetBits
  # Subscribe to subnets for upcoming duties
  for duty in tracker.duties:
    if wallSlot <= duty.slot and
        wallSlot + SUBNET_SUBSCRIPTION_LEAD_TIME_SLOTS > duty.slot:

      res[duty.subnet_id.int] = true
  res

func stabilitySubnets*(tracker: ActionTracker, slot: Slot): AttnetBits =
  if tracker.subscribeAllSubnets:
    allSubnetBits
  else:
    var res: AttnetBits
    for v in tracker.stabilitySubnets:
      res[v.subnet_id.int] = true
    res

func updateSlot*(tracker: var ActionTracker, wallSlot: Slot) =
  # Prune duties from the past - this collection is kept small because there
  # are only so many slot/subnet combos - prune both internal and API-supplied
  # duties at the same time
  tracker.duties.keepItIf(it.slot >= wallSlot)

  # Keep stability subnets for as long as validators are validating
  var toPrune: seq[ValidatorIndex]
  for k, v in tracker.knownValidators:
    if v + KNOWN_VALIDATOR_DECAY < wallSlot: toPrune.add k
  for k in toPrune: tracker.knownValidators.del k

  # One stability subnet per known validator
  static: doAssert RANDOM_SUBNETS_PER_VALIDATOR == 1

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/validator.md#phase-0-attestation-subnet-stability
  let expectedSubnets =
    min(ATTESTATION_SUBNET_COUNT, tracker.knownValidators.len)

  let epoch = wallSlot.epoch
  block:
    # If we have too many stability subnets, remove some expired ones
    var i = 0
    while tracker.stabilitySubnets.len > expectedSubnets and
        i < tracker.stabilitySubnets.len:
      if epoch >= tracker.stabilitySubnets[i].expiration:
        tracker.stabilitySubnets.delete(i)
      else:
        inc i

  for ss in tracker.stabilitySubnets.mitems():
    if epoch >= ss.expiration:
      ss = tracker.randomStabilitySubnet(epoch)

  # and if we have too few, add a few more
  for i in tracker.stabilitySubnets.len..<expectedSubnets:
    tracker.stabilitySubnets.add(tracker.randomStabilitySubnet(epoch))

  tracker.currentSlot = wallSlot

func getNextValidatorAction*(
    actionSlotSource: auto, lastCalculatedEpoch: Epoch, slot: Slot): Slot =
  # The relevant actions are in, depending on calculated bounds:
  # [aS[epoch mod 2], aS[1 - (epoch mod 2)]]
  #  current epoch          next epoch
  let orderedActionSlots = [
    actionSlotSource[     slot.epoch mod 2'u64],
    actionSlotSource[1 - (slot.epoch mod 2'u64)]]

  static: doAssert MIN_ATTESTATION_INCLUSION_DELAY == 1

  # Cleverer ways exist, but a short loop is fine. O(n) vs O(log n) isn't that
  # important when n is 32 or 64, with early exit on average no more than half
  # through.
  for i in [0'u64, 1'u64]:
    let bitmapEpoch = slot.epoch + i

    if bitmapEpoch > lastCalculatedEpoch:
      return FAR_FUTURE_SLOT

    for slotOffset in 0 ..< SLOTS_PER_EPOCH:
      let nextActionSlot =
        compute_start_slot_at_epoch(bitmapEpoch) + slotOffset
      if ((orderedActionSlots[i] and (1'u32 shl slotOffset)) != 0) and
          nextActionSlot > slot:
        return nextActionSlot

  FAR_FUTURE_SLOT

proc updateActions*(tracker: var ActionTracker, epochRef: EpochRef) =
  # Updates the schedule for upcoming attestation and proposal work
  let
    epoch = epochRef.epoch

  if tracker.lastCalculatedEpoch == epoch:
    return
  tracker.lastCalculatedEpoch = epoch

  let validatorIndices = toHashSet(toSeq(tracker.knownValidators.keys()))

  # Update proposals
  tracker.proposingSlots[epoch mod 2] = 0
  for i, proposer in epochRef.beacon_proposers:
    if proposer.isSome and proposer.get() in validatorIndices:
      tracker.proposingSlots[epoch mod 2] =
        tracker.proposingSlots[epoch mod 2] or (1'u32 shl i)

  tracker.attestingSlots[epoch mod 2] = 0

  # The relevant bitmaps are 32 bits each.
  static: doAssert SLOTS_PER_EPOCH <= 32

  for (committeeIndex, subnet_id, slot) in
      get_committee_assignments(epochRef, validatorIndices):

    doAssert compute_epoch_at_slot(slot) == epoch

    # Each get_committee_assignments() call here is on the next epoch. At any
    # given time, only care about two epochs, the current and next epoch. So,
    # after it is done for an epoch, [aS[epoch mod 2], aS[1 - (epoch mod 2)]]
    # provides, sequentially, the current and next epochs' slot schedules. If
    # get_committee_assignments() has not been called for the next epoch yet,
    # typically because there hasn't been a block in the current epoch, there
    # isn't valid information in aS[1 - (epoch mod 2)], and only slots within
    # the current epoch can be known. Usually, this is not a major issue, but
    # when there hasn't been a block substantially through an epoch, it might
    # prove misleading to claim that there aren't attestations known, when it
    # only might be known either way for 3 more slots. However, it's also not
    # as important to attest when blocks aren't flowing as only attestions in
    # blocks garner rewards.
    tracker.attestingSlots[epoch mod 2] =
      tracker.attestingSlots[epoch mod 2] or
        (1'u32 shl (slot mod SLOTS_PER_EPOCH))

proc init*(T: type ActionTracker, rng: ref BrHmacDrbgContext, subscribeAllSubnets: bool): T =
  T(
    rng: rng,
    subscribeAllSubnets: subscribeAllSubnets
  )