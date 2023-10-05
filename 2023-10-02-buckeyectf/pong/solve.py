import multiprocessing
from scapy.layers.inet import *
from scapy.all import *

TARGET = "18.191.205.48"
PACKET_AMOUNT = 3570


def create_ping_packet(seq: int) -> IP:
    return IP(dst=TARGET) / ICMP(seq=seq)


def worker(start_seq, end_seq):
    print(f"Starting processing packets from {start_seq} to {end_seq}")
    data_list = []
    for i in range(start_seq, end_seq):
        packet = create_ping_packet(i)
        response = sr1(packet, verbose=0)

        if not response:
            continue

        if Raw not in response:
            print(f"[!] Missing Raw layer at {i}")
            continue

        data_list.append(response[Raw].load)
    print(
        f"[+] Done! Processed {end_seq - start_seq} packets ({start_seq}-{end_seq})"
    )

    with open(f"pong_{start_seq}.png", "wb") as file:
        file.write(b"".join(data_list))


def main():
    num_workers = 8
    seq_range = PACKET_AMOUNT // num_workers

    processes = []
    for i in range(num_workers):
        start_seq = i * seq_range
        end_seq = (i + 1) * seq_range if i < num_workers - 1 else PACKET_AMOUNT
        process = multiprocessing.Process(
            target=worker, args=(start_seq, end_seq)
        )
        processes.append(process)
        process.start()

    for process in processes:
        process.join()

    with open("pong.png", "wb") as target:
        for i in range(num_workers):
            start_seq = i * seq_range
            with open(f"pong_{start_seq}.png", "rb") as source:
                target.write(source.read())


if __name__ == "__main__":
    main()
