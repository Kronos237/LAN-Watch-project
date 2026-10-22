"""Optional BLE advertisement discovery, distinct from LAN observations."""
from datetime import datetime, timezone
import asyncio

async def scan_ble(timeout=5):
    try:
        from bleak import BleakScanner
        items=await BleakScanner.discover(timeout=timeout,return_adv=True)
        results=[]
        for address,(device,adv) in items.items():
            results.append({"name":adv.local_name or device.name,"identifier":address,"rssi":getattr(adv,"rssi",None),
                            "service_uuids":list(getattr(adv,"service_uuids",[]) or []),
                            "observed_at":datetime.now(timezone.utc).isoformat(),"source":"ble"})
        return results,None
    except Exception as exc:
        return [],str(exc)
