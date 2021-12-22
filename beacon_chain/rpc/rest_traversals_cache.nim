# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronos,
  chronicles,
  ../consensus_object_pools/block_pools_types

type
  CacheEntry = ref object
    state: ref StateData
    lastUsed: Moment

  RestTraversalsCache* = ref object
    entries: seq[CacheEntry]
    ttl: Duration

const
  slotDifferenceForCacheHit = 5 * SLOTS_PER_EPOCH

logScope:
  topics = "rest_traversals_cache"

proc init*(T: type RestTraversalsCache,
           cacheSize: Natural,
           cacheTtl: Duration): T =
  doAssert cacheSize > 0

  RestTraversalsCache(
    entries: newSeq[CacheEntry](cacheSize),
    ttl: cacheTtl)

proc scheduleEntryExpiration(cache: RestTraversalsCache,
                             entryIdx: int) =
  proc removeElement(arg: pointer) =
    if cache.entries[entryIdx] == nil:
      return
    let expirationTime = cache.entries[entryIdx].lastUsed + cache.ttl
    if expirationTime > Moment.now:
      return
    cache.entries[entryIdx] = nil
    debug "Cached REST state expired", index = entryIdx

  discard setTimer(Moment.now + cache.ttl, removeElement)

proc add*(cache: RestTraversalsCache, state: ref StateData) =
  var
    now = Moment.now
    lruTime = now
    index = -1

  for i in 0 ..< cache.entries.len:
    if cache.entries[i] == nil:
      index = i
      break
    if cache.entries[i].lastUsed <= lruTime:
      index = i
      lruTime = cache.entries[i].lastUsed

  doAssert index != -1
  cache.entries[index] = CacheEntry(state: state, lastUsed: now)
  debug "Cached REST state added", index = index

  cache.scheduleEntryExpiration(index)

proc getClosestState*(cache: RestTraversalsCache, slot: Slot): ref StateData =
  var
    bestSlotDifference = Slot.high
    index = -1

  for i in 0 ..< cache.entries.len:
    if cache.entries[i] == nil:
      continue

    let stateSlot = getStateField(cache.entries[i].state.data, slot)
    if stateSlot > slot:
      # We can use only states that can be advanced forward in time.
      continue

    let slotDifference = slot - stateSlot
    if slotDifference > slotDifferenceForCacheHit:
      # The state is too old to be useful as a rewind starting point.
      continue

    if slotDifference < bestSlotDifference:
      bestSlotDifference = slotDifference.Slot
      index = i

  if index == -1:
    return nil

  cache.entries[index].lastUsed = Moment.now
  cache.scheduleEntryExpiration(index)

  return cache.entries[index].state
