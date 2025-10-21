import socket

def is_available(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((ip, port))
            return False
        except ConnectionRefusedError:
            return True
        except socket.error:
            return False

def check_ports_in_file(file_path):
    occupied_ports = []
    bad_format = []

    with open(file_path, 'r') as f:
        for line_number, line in enumerate(f, start=1):
            print(line, end="")
            parts = line.strip().split()
            if len(parts) < 4:
                print(f"Warning: format of line {line_number} is incorrect, skip")
                bad_format.append((line_number, line))
                continue

            try:
                ip = parts[1]
                port = int(parts[3])
            except ValueError:
                print(f"Warning: format of line {line_number} is incorrect, skip")
                bad_format.append((line_number, line))
                continue
            
            for i in range(30):
                if not is_available(ip, port + i):
                    occupied_ports.append((ip, port + i))

    if bad_format:
        print("\033[31m[BAD]\033[0m Following lines are not formatted.")
        for line_num, line in bad_format:
            print(f"line {line_num}: {line}")
    else:
        print("\033[32m[GOOD]\033[0m All listed addresses are well configured.")

    if occupied_ports:
        print("\033[31m[BAD]\033[0m Following addresses are occupied.")
        for ip, port in occupied_ports:
            print(f"ip: {ip}, port: {port}")
    else:
        print("\033[32m[GOOD]\033[0m All listed addresses are available.")


if __name__ == "__main__":
    file_path = 'hosts.config'
    check_ports_in_file(file_path)