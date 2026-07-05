"""Exercises an Eipex adapter with pycomm3 (reference scanner). Prints JSON."""

import json
import os

from pycomm3 import CIPDriver, Services

HOST = os.environ.get("ADAPTER_HOST", "127.0.0.1")
PORT = int(os.environ.get("ADAPTER_PORT", "44821"))

# route_path=False: pycomm3 defaults to encoding its (empty) connection path
# as a two-byte padded EPATH (`\x00\x00`) and tacking it onto the end of
# every unconnected generic_message request. Against a device reached
# directly (no backplane/router hop), those two bytes just become trailing
# garbage appended to request_data. Eipex's adapter reads that as extra
# request data it doesn't expect: GET services see a non-empty data field
# and fall through to "service not supported", and the SET (write) service
# sees 6 bytes for a 4-byte assembly and rejects it as "too much data".
# route_path=False removes the appendix and matches how a device with no
# routing in front of it is actually addressed.
driver = CIPDriver(f"{HOST}:{PORT}")
driver.open()

results = {}

vendor = driver.generic_message(
    service=Services.get_attribute_single,
    class_code=1,
    instance=1,
    attribute=1,
    connected=False,
    route_path=False,
    name="vendor",
)
results["vendor"] = list(vendor.value) if vendor.value else None
results["vendor_ok"] = vendor.error is None

write = driver.generic_message(
    service=Services.set_attribute_single,
    class_code=4,
    instance=150,
    attribute=3,
    request_data=b"\xaa\xbb\xcc\xdd",
    connected=False,
    route_path=False,
    name="write",
)
results["write_ok"] = write.error is None

read = driver.generic_message(
    service=Services.get_attribute_single,
    class_code=4,
    instance=150,
    attribute=3,
    connected=False,
    route_path=False,
    name="read",
)
results["readback_ok"] = (
    bytes(read.value) == b"\xaa\xbb\xcc\xdd" if read.value else False
)

bad = driver.generic_message(
    service=Services.get_attribute_single,
    class_code=0x77,
    instance=1,
    attribute=1,
    connected=False,
    route_path=False,
    name="unknown_class",
)
results["unknown_class_errors"] = bad.error is not None

driver.close()
print(json.dumps(results))
