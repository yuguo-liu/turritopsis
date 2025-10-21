import time
import os
import json
import datetime
import pprint
import argparse

def total_dict_length(d):
    count = 0
    if isinstance(d, dict):
        count += len(d)
        for value in d.values():
            count += total_dict_length(value)
    if isinstance(d, list):
        for elem in d:
            count += total_dict_length(elem)
    return count

def get_log_dynamic(state, lines, id):
    assert state == "not reading" or state == "reading", "wrong format state"
    with open(f"log/consensus-node-{id}.log", "r") as lf:
        logs = lf.readlines()
    new_lines = len(logs)
    if new_lines == 0:
        return False, lines, state, {
            "summary": None,
            "info by round": None
        }, None
    
    logs = [l.split("INFO ")[1] for l in logs]
    node_data = []
    summary = None
    average = None
    is_terminated = False
    for l in logs:
        if state == "not reading" and l.startswith(f'nodes start round'):
            state = "reading"
        if state == "reading" and l.startswith(f"Node {id} Delivers"):
            txs = l.split(" ")[10]
            node_data.append({
                "txs": int(txs)
            })
        if state == "reading" and l.startswith(f"round"):
            latency = l.split(" ")[-2]
            node_data[-1]["latency"] = float(latency)
            node_data[-1]["tps"] = node_data[-1]["txs"] / node_data[-1]["latency"]
        if state == "reading" and l.startswith(f"Node {id} counting"):
            sofar_tps = l.split(" ")[5].split(",")[0]
            sofar_latency = l.split(" ")[-2]
            node_data[-1]["sofar_tps"] = float(sofar_tps)
            node_data[-1]["sofar_latency"] = float(sofar_latency)
        if state == "reading" and l.startswith("tps: "):
            average = {
                "tps": float(l.split(' ')[1].split(",")[0]),
                "latency": float(l.split(' ')[3].split('\n')[0])
            }
        if state == "reading" and l.startswith(f"node {id} breaks "):
            summary = {
                "running time": float(l.split(" ")[4]),
                "txs": int(l.split(" ")[10].split(",")[0]),
                "latency": float(l.split(" ")[12].split(",")[0]),
                "tps": float(l.split(" ")[-2])
            }
        if l.startswith("set stop as true"):
            is_terminated = True
    last_line = logs[-1]
    if last_line.startswith(f"Node {id} Delivers"):
        new_lines -= 1
        node_data = node_data[:-1]
    if last_line.startswith("round"):
        new_lines -= 2
        node_data = node_data[:-1]
    
    return is_terminated, new_lines, state, {
        "summary": summary,
        "info by round": node_data
    }, average


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--N', metavar='N', required=True,
                        help='Total number of nodes', type=int)
    args = parser.parse_args()
    N = args.N

    log_files = []
    while len(log_files) < N:
        log_files = [
            f"{os.getcwd()}/log/" + file for file in os.listdir(f"{os.getcwd()}/log")
            if file.startswith("consensus-node-")
        ]
    log_files = sorted(log_files)
    print(log_files)
    num_log_files = len(log_files)

    lines = [0 for _ in range(num_log_files)]
    state = ["not reading" for _ in range(num_log_files)]
    is_ternimated = [False for _ in range(num_log_files)]
    info = [None for _ in range(num_log_files)]
    average = None
    epoch = 0
    while True:
        epoch += 1
        time.sleep(1)
        print("="*50, "catch log", "="*50)
        nodes_info = {}
        for id in range(num_log_files):
            node_data = None
            summary = None
            is_ternimated[id], lines[id], state[id], info[id], average = get_log_dynamic(state[id], lines[id], id)
            nodes_info[f"node-{id}"] = info[id]
            if average is not None:
                nodes_info["average"] = average
        
        # pprint.pprint(nodes_info)
        print(f"epoch {epoch}, get info length: {total_dict_length(nodes_info)}")
        with open(f"{os.getcwd()}/parse_log/result-sdumbo.json", "w") as j:
            json.dump(nodes_info, j, indent=4, sort_keys=True)

        if False not in is_ternimated:
            break