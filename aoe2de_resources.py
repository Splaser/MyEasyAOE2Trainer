#!/usr/bin/env python3
"""
AoE2DE resource DValue helper (current build)

What is already known from runtime reversing:
- WorldPlayer + 0x98 -> indexed encrypted value table
- table stride = 8 bytes
- FACT 5..8 map to table slots 0..3:
    FACT 5 -> +0x00
    FACT 6 -> +0x08
    FACT 7 -> +0x10
    FACT 8 -> +0x18
- each slot is an encrypted uint64
- low 32 bits of the decrypted uint64 are interpreted as float32
- codec:
    xor K1
    xor K2
    sub K3
    xor K4

Still unknown:
- stable way to resolve the local WorldPlayer* pointer

Once local_player is known, pass it with --local-player 0x...
"""

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass

import pymem


PROCESS_NAME = "AoE2DE_s.exe"

MASK64 = 0xFFFFFFFFFFFFFFFF
LOW32_MASK = 0xFFFFFFFF
HIGH32_MASK = 0xFFFFFFFF00000000

K1 = 0x6AE24D3352F04511
K2 = 0xC22D6B496D833977
K3 = 0x042AC42976FCCEF5
K4 = 0xA9834B738A7DD167

WORLDPLAYER_VALUE_TABLE_OFFSET = 0x98
VALUE_STRIDE = 0x08

SLOT_NAMES = {
    0: "food",
    1: "wood",
    2: "stone",
    3: "gold",
    4: "population_free",
    5: "conversion_range",
    6: "current_age",
    7: "relics_captured",
    8: "special_08",
    9: "trade_goods",
    10: "unused_10",
    11: "population_used",
}

FACT_TO_SLOT = {
    5: 0,
    6: 1,
    7: 2,
    8: 3,
}

PLAYER_MANAGER_RVA = 0x42A5FB0
CURRENT_PLAYER_RVA = 0x42A5FC0

PLAYER_VECTOR_BEGIN_OFFSET = 0x768
PLAYER_VECTOR_END_OFFSET = 0x770
PLAYER_ENTRY_STRIDE = 0x10



def u32_to_float(value: int) -> float:
    return struct.unpack("<f", struct.pack("<I", value & LOW32_MASK))[0]


def float_to_u32(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", float(value)))[0]


def decrypt_raw(enc: int) -> int:
    """Decrypt one encrypted 64-bit DValue payload."""
    x = enc & MASK64
    x ^= K1
    x ^= K2
    x = (x - K3) & MASK64
    x ^= K4
    return x & MASK64


def encrypt_raw(dec: int) -> int:
    """Inverse of decrypt_raw()."""
    x = dec & MASK64
    x ^= K4
    x = (x + K3) & MASK64
    x ^= K2
    x ^= K1
    return x & MASK64


def decrypt_float(enc: int) -> float:
    """Decrypt and interpret the low 32 bits as IEEE-754 float32."""
    dec = decrypt_raw(enc)
    return u32_to_float(dec)


def replace_decrypted_float(dec: int, new_value: float) -> int:
    """
    Replace only the low 32 bits of an already-decrypted uint64.
    Preserve the high 32 bits exactly as they currently exist.
    """
    bits = float_to_u32(new_value)
    return (dec & HIGH32_MASK) | bits


@dataclass
class SlotValue:
    slot: int
    fact_id: int
    address: int
    encrypted: int
    decrypted: int
    value: float


class AoE2ResourceAccessor:
    def __init__(self, pm: pymem.Pymem, local_player: int):
        self.pm = pm
        self.local_player = local_player

    def get_value_table(self) -> int:
        table = self.pm.read_ulonglong(
            self.local_player + WORLDPLAYER_VALUE_TABLE_OFFSET
        )
        if not table:
            raise RuntimeError(
                f"WorldPlayer+0x{WORLDPLAYER_VALUE_TABLE_OFFSET:X} returned NULL"
            )
        return table

    def slot_address(self, slot: int) -> int:
        if slot < 0:
            raise ValueError("slot must be >= 0")
        return self.get_value_table() + slot * VALUE_STRIDE

    def read_slot(self, slot: int) -> SlotValue:
        table = self.get_value_table()
        addr = table + slot * VALUE_STRIDE

        enc = self.pm.read_ulonglong(addr)
        dec = decrypt_raw(enc)
        value = u32_to_float(dec)

        fact_id = next(
            (fid for fid, s in FACT_TO_SLOT.items() if s == slot),
            -1,
        )

        return SlotValue(
            slot=slot,
            fact_id=fact_id,
            address=addr,
            encrypted=enc,
            decrypted=dec,
            value=value,
        )

    def read_resource_slots(self) -> list[SlotValue]:
        return [
            self.read_slot(0),
            self.read_slot(1),
            self.read_slot(2),
            self.read_slot(3),
            self.read_slot(4),   # +0x20
            self.read_slot(11),  # +0x58
        ]

    def read_population(self) -> tuple[float, float, float]:
        free = self.read_slot(4).value
        used = self.read_slot(11).value
        limit = used + free

        return used, limit, free


    def write_slot(self, slot: int, new_value: float) -> SlotValue:
        """
        Safely update a slot:
        1. read current encrypted qword
        2. decrypt full uint64
        3. replace only low float32 bits
        4. preserve current decrypted high 32 bits
        5. re-encrypt full uint64
        6. write qword back
        """
        table = self.get_value_table()
        addr = table + slot * VALUE_STRIDE

        old_enc = self.pm.read_ulonglong(addr)
        old_dec = decrypt_raw(old_enc)

        new_dec = replace_decrypted_float(old_dec, new_value)
        new_enc = encrypt_raw(new_dec)

        self.pm.write_ulonglong(addr, new_enc)

        return self.read_slot(slot)

    def write_fact(self, fact_id: int, new_value: float) -> SlotValue:
        if fact_id not in FACT_TO_SLOT:
            raise ValueError(
                f"Only FACT IDs {sorted(FACT_TO_SLOT)} are currently mapped"
            )
        return self.write_slot(FACT_TO_SLOT[fact_id], new_value)


def parse_int(value: str) -> int:
    return int(value, 0)





def print_slots(accessor: AoE2ResourceAccessor) -> None:
    table = accessor.get_value_table()

    print(f"local_player : 0x{accessor.local_player:X}")
    print(f"value_table  : 0x{table:X}")
    print()

    for item in accessor.read_resource_slots():
        name = SLOT_NAMES.get(item.slot, "?")

        print(
            f"slot {item.slot} "
            f"({name}, FACT {item.fact_id}) "
            f"addr=0x{item.address:X} "
            f"enc=0x{item.encrypted:016X} "
            f"dec=0x{item.decrypted:016X} "
            f"value={item.value}"
        )


    used, limit, free = accessor.read_population()

    print(
        f"population: "
        f"{used:g}/{limit:g} "
        f"(free={free:g})"
    )


def enumerate_players(pm: pymem.Pymem) -> None:
    import pymem.process

    mod = pymem.process.module_from_name(
        pm.process_handle,
        PROCESS_NAME,
    )

    base = mod.lpBaseOfDll

    for rva in [
        0x42A5F90,
        0x42A5FA0,
        0x42A5FA8,
        0x42A5FB0,
        0x42A5FB8,
        0x42A5FC0,
    ]:
        addr = base + rva

        try:
            value = pm.read_ulonglong(addr)
            print(
                f"global RVA 0x{rva:X} "
                f"@ 0x{addr:X} "
                f"= 0x{value:X}"
            )
        except Exception as e:
            print(
                f"global RVA 0x{rva:X}: "
                f"ERROR {e}"
            )

    print()

    manager_ptr_addr = base + PLAYER_MANAGER_RVA
    manager = pm.read_ulonglong(manager_ptr_addr)

    if not manager:
        print(
            f"PlayerManager global at "
            f"0x{manager_ptr_addr:X} is NULL"
        )
        return

    begin = pm.read_ulonglong(
        manager + PLAYER_VECTOR_BEGIN_OFFSET
    )

    end = pm.read_ulonglong(
        manager + PLAYER_VECTOR_END_OFFSET
    )

    if not begin or not end:
        raise RuntimeError("Player vector begin/end is NULL")

    if end < begin:
        raise RuntimeError(
            f"Invalid player vector: begin=0x{begin:X}, end=0x{end:X}"
        )

    size = end - begin

    if size % PLAYER_ENTRY_STRIDE != 0:
        print(
            f"warning: vector size 0x{size:X} "
            f"is not aligned to stride 0x{PLAYER_ENTRY_STRIDE:X}"
        )

    count = size // PLAYER_ENTRY_STRIDE

    print(f"module_base   : 0x{base:X}")
    print(f"manager_ptr   : 0x{manager_ptr_addr:X}")
    print(f"manager       : 0x{manager:X}")
    print(f"players_begin : 0x{begin:X}")
    print(f"players_end   : 0x{end:X}")
    print(f"player_count  : {count}")
    print()

    for i in range(count):
        entry = begin + i * PLAYER_ENTRY_STRIDE

        try:
            world_player = pm.read_ulonglong(entry)
        except Exception as e:
            print(
                f"[{i}] entry=0x{entry:X} "
                f"ERROR reading WorldPlayer*: {e}"
            )
            continue

        if not world_player:
            print(
                f"[{i}] entry=0x{entry:X} "
                f"WorldPlayer=NULL"
            )
            continue

        try:
            accessor = AoE2ResourceAccessor(
                pm,
                world_player,
            )

            table = accessor.get_value_table()
            slots = accessor.read_resource_slots()

            values = [
                item.value
                for item in slots
            ]

            print(
                f"[{i}] "
                f"entry=0x{entry:X} "
                f"WorldPlayer=0x{world_player:X} "
                f"table=0x{table:X} "
                f"slots={values}"
            )

        except Exception as e:
            print(
                f"[{i}] "
                f"entry=0x{entry:X} "
                f"WorldPlayer=0x{world_player:X} "
                f"ERROR: {e}"
            )


def resolve_local_player_sp(pm: pymem.Pymem) -> int:
    import pymem.process

    mod = pymem.process.module_from_name(
        pm.process_handle,
        PROCESS_NAME,
    )
    base = mod.lpBaseOfDll

    manager = pm.read_ulonglong(
        base + PLAYER_MANAGER_RVA
    )

    if not manager:
        raise RuntimeError(
            "PlayerManager is NULL. "
            "Make sure a single-player match is loaded."
        )

    begin = pm.read_ulonglong(
        manager + PLAYER_VECTOR_BEGIN_OFFSET
    )

    end = pm.read_ulonglong(
        manager + PLAYER_VECTOR_END_OFFSET
    )

    if not begin or not end:
        raise RuntimeError("Player vector is not initialized")

    count = (end - begin) // PLAYER_ENTRY_STRIDE

    if count < 2:
        raise RuntimeError(
            f"Unexpected player count: {count}"
        )

    # Single-player/skirmish convention:
    # index 0 = Gaia
    # index 1 = local human player
    local_player = pm.read_ulonglong(
        begin + PLAYER_ENTRY_STRIDE
    )

    if not local_player:
        raise RuntimeError("Player[1] is NULL")

    # sanity check
    table = pm.read_ulonglong(
        local_player + WORLDPLAYER_VALUE_TABLE_OFFSET
    )

    if not table:
        raise RuntimeError(
            "Player[1] does not look like a valid WorldPlayer"
        )

    return local_player


def resolve_current_player_context(pm: pymem.Pymem) -> int:
    import pymem.process

    mod = pymem.process.module_from_name(
        pm.process_handle,
        PROCESS_NAME,
    )

    base = mod.lpBaseOfDll

    local_player = pm.read_ulonglong(
        base + CURRENT_PLAYER_RVA
    )

    if not local_player:
        raise RuntimeError(
            "Local WorldPlayer is NULL. "
            "Make sure a match is currently loaded."
        )

    # sanity check:
    # WorldPlayer + 0x98 must contain a valid value-table pointer.
    table = pm.read_ulonglong(
        local_player + WORLDPLAYER_VALUE_TABLE_OFFSET
    )

    if not table:
        raise RuntimeError(
            f"Candidate WorldPlayer 0x{local_player:X} "
            f"has NULL value table at +0x{WORLDPLAYER_VALUE_TABLE_OFFSET:X}"
        )

    return local_player


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AoE2DE encrypted resource-slot reader/writer"
    )

    parser.add_argument(
        "--local-player",
        type=parse_int,
        help="Runtime WorldPlayer* address, e.g. 0x123456789ABC",
    )

    parser.add_argument(
        "--enumerate-players",
        action="store_true",
        help="Enumerate all WorldPlayer objects from the global player manager",
    )

    group = parser.add_mutually_exclusive_group()

    group.add_argument(
        "--food",
        type=float,
        metavar="VALUE",
        help="Set food",
    )

    group.add_argument(
        "--wood",
        type=float,
        metavar="VALUE",
        help="Set wood",
    )

    group.add_argument(
        "--stone",
        type=float,
        metavar="VALUE",
        help="Set stone",
    )

    group.add_argument(
        "--gold",
        type=float,
        metavar="VALUE",
        help="Set gold",
    )

    group.add_argument(
        "--all",
        dest="all_resources",
        type=float,
        metavar="VALUE",
        help="Set food, wood, stone and gold to VALUE",
    )

    group.add_argument(
        "--population",
        type=float,
        metavar="LIMIT",
        help="Set population limit by adjusting population_free",
    )

    group.add_argument(
        "--reset-population",
        type=float,
        metavar="LIMIT",
        help="Reset used population to 0 and set population capacity to LIMIT",
    )

    args = parser.parse_args()

    pm = pymem.Pymem(PROCESS_NAME)

    try:
        if args.enumerate_players:
            enumerate_players(pm)
            return

        if args.local_player is not None:
            local_player = args.local_player
        else:
            local_player = resolve_local_player_sp(pm)

        accessor = AoE2ResourceAccessor(
            pm,
            local_player,
        )

        if args.food is not None:
            result = accessor.write_slot(0, args.food)

            print(
                f"food: {result.value:g} "
                f"addr=0x{result.address:X}"
            )
            print()

        elif args.wood is not None:
            result = accessor.write_slot(1, args.wood)

            print(
                f"wood: {result.value:g} "
                f"addr=0x{result.address:X}"
            )
            print()

        elif args.stone is not None:
            result = accessor.write_slot(2, args.stone)

            print(
                f"stone: {result.value:g} "
                f"addr=0x{result.address:X}"
            )
            print()

        elif args.gold is not None:
            result = accessor.write_slot(3, args.gold)

            print(
                f"gold: {result.value:g} "
                f"addr=0x{result.address:X}"
            )
            print()

        elif args.all_resources is not None:
            value = args.all_resources

            for slot in range(4):
                result = accessor.write_slot(slot, value)
                name = SLOT_NAMES[slot]

                print(
                    f"{name}: {result.value:g} "
                    f"addr=0x{result.address:X}"
                )

            print()

        elif args.population is not None:
            target_limit = args.population

            used = accessor.read_slot(11).value
            free = target_limit - used

            if free < 0:
                raise ValueError(
                    f"Population limit {target_limit:g} "
                    f"is below current population {used:g}"
                )

            result = accessor.write_slot(4, free)

            print(
                f"population: "
                f"{used:g}/{target_limit:g} "
                f"(free={result.value:g}) "
                f"addr=0x{result.address:X}"
            )
            print()

        elif args.reset_population is not None:
            target_limit = args.reset_population

            if target_limit < 0:
                raise ValueError(
                    "Population limit must be >= 0"
                )

            used_result = accessor.write_slot(11, 0.0)
            free_result = accessor.write_slot(4, target_limit)

            print(
                f"population reset: "
                f"0/{target_limit:g} "
                f"(used={used_result.value:g}, "
                f"free={free_result.value:g})"
            )
            print()


        print_slots(accessor)

    finally:
        try:
            pm.close_process()
        except Exception:
            pass


if __name__ == "__main__":
    main()
