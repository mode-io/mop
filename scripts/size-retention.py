"""Estimate history capacity from review rate, desired window and memory budget."""
import argparse,json,math

def size_history(rate, minutes=15, headroom=1.5, budget_mib=128, bytes_per_record=16384):
    if any(not math.isfinite(v) or v <= 0 for v in (rate, minutes, headroom, budget_mib, bytes_per_record)):
        raise ValueError("all sizing inputs must be finite and positive")
    required = math.ceil(rate * minutes * 60 * headroom)
    desired = math.ceil(required / 1024) * 1024
    memory_cap = math.floor(budget_mib * 1048576 / bytes_per_record)
    cap = min(memory_cap, 100000)
    rounded_cap = cap // 1024 * 1024 if cap >= 1024 else cap
    selected = min(desired, rounded_cap)
    if selected < 1: raise ValueError("budget cannot hold one record")
    return {"rate_per_second": rate, "target_minutes": minutes, "headroom": headroom,
            "raw_required_records": required, "recommended_history_limit": selected,
            "memory_budget_mib": budget_mib, "assumed_bytes_per_record": bytes_per_record,
            "estimated_history_mib": selected * bytes_per_record / 1048576,
            "window_minutes_at_rate": selected / rate / 60,
            "target_with_headroom_met": selected >= required,
            "note": "History-only budget; process index, queues, UI snapshots and base runtime need additional memory. Estimate, not an RSS guarantee."}

if __name__ == '__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--rate',type=float,required=True,help='observed completed judgments per second')
    p.add_argument('--minutes',type=float,default=15)
    p.add_argument('--headroom',type=float,default=1.5)
    p.add_argument('--budget-mib',type=float,default=128)
    p.add_argument('--bytes-per-record',type=float,default=16384)
    args=p.parse_args()
    print(json.dumps(size_history(args.rate,args.minutes,args.headroom,args.budget_mib,args.bytes_per_record),indent=2))
