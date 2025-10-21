import glob
import time
import os

def count_log_lines():
    total_lines = 0
    for filepath in glob.glob("log/consensus-node-*.log"):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                total_lines += sum(1 for _ in f)
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
    return total_lines

def monitor_logs():
    unchanged_count = 0
    last_count = -1  # Initialize to a value that will not match the first count

    while unchanged_count < 10:
        current_count = count_log_lines()
        print(f"Total log lines: {current_count}")
        
        if current_count == last_count:
            unchanged_count += 1
        else:
            unchanged_count = 0
            last_count = current_count
        
        time.sleep(1)

    print("No change in line count for 10 checks. Stopping monitor.")

if __name__ == "__main__":
    monitor_logs()
