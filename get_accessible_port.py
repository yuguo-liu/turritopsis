import socket
import random

def get_multiple_available_ports(count=5, start_port=1024, end_port=65535, max_retries=1000):
    used_ports = set()
    available_ports = []
    
    for _ in range(max_retries):
        if len(available_ports) >= count:
            break
            
        port = random.randint(start_port, end_port)
        if port in used_ports:
            continue
            
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                available_ports.append(port)
                used_ports.add(port)
            except OSError:
                used_ports.add(port)
                continue
    
    if len(available_ports) < count:
        raise RuntimeError(f"仅找到 {len(available_ports)} 个可用端口（尝试 {max_retries} 次）")
    
    return available_ports

if __name__ == '__main__':
    ports = get_multiple_available_ports(64)
    print("可用端口列表:", ports)
    with open("hosts.config", "w") as h:
        h.write

