
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Validator for consensus log files whose length/content vary per execution.

Usage:
  python validate_consensus_log.py /path/to/consensus-node-0.log
Exit code is 0 if valid, 1 if invalid.
"""

import re
import sys
import json
from collections import defaultdict, Counter

LINE_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) '
    r'(?P<file>[\w\.\-]+) \[line:(?P<line>\d+)\] '
    r'(?P<func>\w+) (?P<level>\w+) (?P<msg>.*)$'
)

def parse_node_id_from_msg(msg):
    # Try several patterns found in sample logs
    pats = [
        r'node id (\d+)',
        r'Node (\d+) ',
        r'node (\d+)\'s starts to run consensus',
        r'Node (\d+) starts to run',
    ]
    for p in pats:
        m = re.search(p, msg)
        if m:
            return int(m.group(1))
    return None

def main(path):
    issues = []
    warnings = []
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        lines = [line.rstrip('\n') for line in f]

    if not lines:
        issues.append("文件为空")
        return report(False, issues, warnings)

    # Basic format validation
    bad_format_idx = []
    parsed = []
    for i, line in enumerate(lines, start=1):
        m = LINE_RE.match(line)
        if not m:
            bad_format_idx.append(i)
            continue
        parsed.append(m.groupdict())

    if bad_format_idx:
        issues.append(f"有 {len(bad_format_idx)} 行不符合通用格式（示例：时间 日志源 [line:X] 函数 等级 消息）。前3个错误行号：{bad_format_idx[:3]}")

    # Extract node ids and key milestones
    node_ids = []
    milestones = {
        "run_consensus": False,          # "starts to run consensus"
        "dummy_loaded": False,           # "completed the loading of dummy TXs"
        "run_bft_start_time": False,     # "starts to run at time:"
    }

    # Round tracking
    start_rounds = []
    deliver_rounds = []
    round_time_rounds = []
    tps_rounds = []

    for d in parsed:
        msg = d["msg"]

        nid = parse_node_id_from_msg(msg)
        if nid is not None:
            node_ids.append(nid)

        if "starts to run consensus" in msg:
            milestones["run_consensus"] = True
        if "completed the loading of dummy TXs" in msg:
            milestones["dummy_loaded"] = True
        if "starts to run at time:" in msg:
            milestones["run_bft_start_time"] = True

        m = re.search(r'nodes start round (\d+)', msg)
        if m:
            start_rounds.append(int(m.group(1)))
        m = re.search(r'Delivers ACS Block in Round (\d+)', msg)
        if m:
            deliver_rounds.append(int(m.group(1)))
        m = re.search(r'round (\d+) time:', msg)
        if m:
            round_time_rounds.append(int(m.group(1)))
        m = re.search(r'counting so-far tps:', msg)
        if m:
            # Try to also capture the round number for this tps log if present nearby
            m2 = re.search(r'Node \d+ counting so-far tps: .*', msg)
            # No round number in the same line, we will align later by order.
            tps_rounds.append(None)

    # Node id consistency check
    if node_ids:
        id_counts = Counter(node_ids)
        most_common_id, freq = id_counts.most_common(1)[0]
        if len(id_counts) > 1:
            warnings.append(f"检测到多个节点ID {sorted(id_counts.keys())}；以出现次数最多的 {most_common_id} 作为当前日志主体（出现 {freq} 次）。")
    else:
        warnings.append("未在日志消息中解析到任何节点ID。")

    # Milestone checks
    for key, ok in milestones.items():
        if not ok:
            human = {
                "run_consensus": "缺少启动共识的标记（starts to run consensus）",
                "dummy_loaded": "缺少完成加载dummy TXs的标记（completed the loading of dummy TXs）",
                "run_bft_start_time": "缺少BFT启动时间标记（starts to run at time:）",
            }[key]
            issues.append(human)

    # Round sequence checks
    def check_sequential(name, arr):
        if not arr:
            return [f"缺少 {name} 日志。"]
        gaps = []
        # Allow starting at 0 or another number, but require step of +1
        for i in range(1, len(arr)):
            if arr[i] != arr[i-1] + 1:
                gaps.append((arr[i-1], arr[i]))
        out = []
        if gaps:
            out.append(f"{name} 序列不是严格递增步长1（示例间断: {gaps[:3]}）")
        return out

    # We will consider deliver_rounds as the canonical set of completed rounds
    issues += check_sequential("Deliver(区块交付)", deliver_rounds)

    # "nodes start round" should cover the same or more rounds; if fewer, warn
    if start_rounds and deliver_rounds:
        if min(start_rounds) > min(deliver_rounds) or max(start_rounds) < max(deliver_rounds):
            warnings.append("开始轮次与交付轮次范围不一致。")
        # Optional: ensure each delivered round had a 'round X time' entry
        missing_time = sorted(set(deliver_rounds) - set(round_time_rounds))
        if missing_time:
            warnings.append(f"{len(missing_time)} 个轮次缺少 round time 日志（示例: {missing_time[:5]}）。")

    # Simple sanity: throughput lines should be at least as many as delivered rounds (or close)
    if deliver_rounds and tps_rounds and len(tps_rounds) + 5 < len(deliver_rounds):
        warnings.append(f"TPS统计行({len(tps_rounds)})明显少于交付轮次({len(deliver_rounds)})。")

    is_valid = not issues

    result = {
        "file": path,
        "valid": is_valid,
        "issues": issues,
        "warnings": warnings,
        "rounds": {
            "first_delivered_round": deliver_rounds[0] if deliver_rounds else None,
            "last_delivered_round": deliver_rounds[-1] if deliver_rounds else None,
            "delivered_count": len(deliver_rounds),
        }
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return is_valid

def report(valid, issues, warnings):
    result = {
        "valid": valid,
        "issues": issues,
        "warnings": warnings,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return valid

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python validate_consensus_log.py N")
        sys.exit(2)
    N = int(sys.argv[1])
    log_files = [f"log/consensus-node-{i}.log" for i in range(N)]
    is_valids = []
    for f in log_files:
        is_valids.append(main(f))
    
    valid_count = 0
    for f, is_valid in zip(log_files, is_valids):
        if is_valid:
            print(f"\033[32m[Good]\033[0m {f} is valid")
            valid_count += 1
        else:
            print(f"\033[31m[Bad]\033[0m {f} is not valid")

    if valid_count == len(is_valids):
        print(f"\033[32m[Pass]\033[0m Log test is passed")
    else:
        print(f"\033[31m[Fail]\033[0m Log test is not passed")
