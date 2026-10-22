"""Transparent connectivity score (not a security rating)."""
WEIGHTS = {"gateway": .40, "latency": .25, "packet_loss": .20, "dns": .15}

def health_score(*, gateway_reachable=None, latency_ms=None, packet_loss_pct=None, dns_responsive=None):
    vals = {"gateway": None if gateway_reachable is None else (100.0 if gateway_reachable else 0.0),
            "latency": None if latency_ms is None else max(0.0, min(100.0, 100.0*(1-float(latency_ms)/500.0))),
            "packet_loss": None if packet_loss_pct is None else max(0.0, min(100.0, 100.0-float(packet_loss_pct))),
            "dns": None if dns_responsive is None else (100.0 if dns_responsive else 0.0)}
    available = {k:v for k,v in vals.items() if v is not None}
    if len(available) < 2: return {"score": None, "status": "insufficient_data", "contributions": {k:None for k in vals}}
    denom = sum(WEIGHTS[k] for k in available)
    contrib = {k:(WEIGHTS[k]/denom*v if v is not None else None) for k,v in vals.items()}
    return {"score": round(sum(value for value in contrib.values() if value is not None), 1), "status": "measured_connectivity", "contributions": contrib,
            "formula": "gateway 40%, latency 25% (0 ms=100, 500+ ms=0), packet loss 20% (0%=100), DNS 15%; available weights renormalized"}
