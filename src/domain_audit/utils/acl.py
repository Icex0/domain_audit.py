"""Active Directory ACL evaluation helpers (built on impacket's SD parser)."""

import uuid
from typing import Dict, Iterable, Optional

from impacket.ldap import ldaptypes

# Access mask bits (MS-DTYP / MS-ADTS)
ADS_RIGHT_DS_CREATE_CHILD = 0x00000001
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
GENERIC_ALL = 0x10000000

# ACE header flag: the ACE only applies to child objects, not to the object itself
INHERIT_ONLY_ACE = 0x08
# Object ACE flag: ObjectType GUID is present
ACE_OBJECT_TYPE_PRESENT = 0x1

ACCESS_ALLOWED_ACE_TYPE = 0x00
ACCESS_DENIED_ACE_TYPE = 0x01
ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
_ALLOW_TYPES = (ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE)
_SUPPORTED_TYPES = _ALLOW_TYPES + (ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE)

# Controls for requesting nTSecurityDescriptor (LDAP_SERVER_SD_FLAGS_OID)
SD_FLAGS_DACL = [('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x04')]
SD_FLAGS_OWNER_GROUP_DACL = [('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x07')]


def right_decisions(sd_raw: bytes, rights: int, object_guid: Optional[str] = None,
                    sids: Optional[Iterable[str]] = None) -> Dict[str, bool]:
    """Return {sid: allowed} for every SID whose ACEs decide `rights` on the object itself.

    - Inherit-only ACEs are skipped (they don't apply to the object itself).
    - GENERIC_ALL counts as granting every right.
    - Object ACEs (types 5/6) count when they have no ObjectType, or when their
      ObjectType equals `object_guid` (a class GUID for CreateChild, an extended
      right GUID for ControlAccess). InheritedObjectType only limits which
      children inherit the ACE, so it is ignored for the object itself.
    - ACEs are evaluated in DACL order (AD keeps them in canonical order:
      explicit deny, explicit allow, inherited deny, inherited allow); the first
      ACE that decides the right for a SID wins.
    - This evaluates SIDs individually; it does not expand group membership.
    """
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_raw)
    wanted = {s for s in sids} if sids is not None else None
    decisions: Dict[str, bool] = {}
    if not sd['Dacl']:
        return decisions
    object_guid = object_guid.lower() if object_guid else None

    for ace in sd['Dacl'].aces:
        ace_type = ace['AceType']
        if ace_type not in _SUPPORTED_TYPES or ace['AceFlags'] & INHERIT_ONLY_ACE:
            continue
        body = ace['Ace']
        sid = body['Sid'].formatCanonical()
        if sid in decisions or (wanted is not None and sid not in wanted):
            continue
        mask = body['Mask']['Mask']
        if not (mask & rights or mask & GENERIC_ALL):
            continue
        if ace_type in (ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE) \
                and body.hasFlag(ACE_OBJECT_TYPE_PRESENT):
            ace_guid = str(uuid.UUID(bytes_le=bytes(body['ObjectType'])))
            if ace_guid != object_guid:
                continue
        decisions[sid] = ace_type in _ALLOW_TYPES

    return decisions
