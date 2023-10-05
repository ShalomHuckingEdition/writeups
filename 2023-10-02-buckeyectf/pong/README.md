# pong
```
18.191.205.48
```

Based on the fact the challenge is called `pong`, and we are given an IP, it's
probably related to the `ping` command. Let's try:
```sh
PING 18.191.205.48 (18.191.205.48) 56(84) bytes of data.
128 bytes from 18.191.205.48: icmp_seq=1 ttl=29 time=171 ms
128 bytes from 18.191.205.48: icmp_seq=2 ttl=29 time=171 ms
128 bytes from 18.191.205.48: icmp_seq=3 ttl=29 time=170 ms
128 bytes from 18.191.205.48: icmp_seq=4 ttl=29 time=170 ms
^C
--- 18.191.205.48 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 169.554/170.587/171.499/0.744 ms
```
Ok, it works! But what do we do from now? Let's try to open `wireshark` and
look at the packets.
The interesting part is probably not in the ping requests, but in the responses,
so let's focus on them.
Here is a sample of the 3 first responses (ascii)
```
...........p....
E.....@...q....0
.......X.....P.e
.....6..........
............ !"#
$%&'()*+,-./0123
4567x.mP...0..g.
...;x..Q..t.b..$
.I.rG..8..7.:(.H
^..R. U*5+..m..2
.@V.

...........p....
E.....@...p....0
......h..... P.e
....">..........
............ !"#
$%&'()*+,-./0123
4567`/<..2.-..Z<
....3.fU>....z..
x&......E.......
.)......r.a=....
=..m

...........p....
E....c@...p....0
.......4....!P.e
.....B..........
............ !"#
$%&'()*+,-./0123
4567.|.....g....
N.......0p..Z$N.
t.&...........'U
Yqu.|.....zTXtRa
w pr
```

It looks like it's some data passed to us!

Actually, if we get a bigger sample, some of the packets even contain text like
`com.adobe.xmp` which hints that it's a some kind of image being transmitted.

But how does the server know what packet to send to us? Looking at wireshark
once more we notice that our packets contain a `seq` number, which increments
each time.

I didn't manage to get the `ping` installed on my system to send requests with
a custom seq, so let's use python and `scapy` to do so.

Let's define our target ip and create a utility function which creates a ping
request for a given seq.
```py
from scapy.layers.inet import *
from scapy.all import *

TARGET = "18.191.205.48"

def create_ping_packet(seq: int) -> IP:
    return IP(dst=TARGET) / ICMP(seq=seq)
```
Note: you might have to run python as root to give scapy access to sending low
level network packets.
Interestingly, sending a request with seq=0, we get the following:
```py
>>> response = sr1(create_ping_packet(seq=0))
Begin emission:
Finished sending 1 packets.
.............................................................*
Received 62 packets, got 1 answers, remaining 0 packets
>>> response.show()
###[ IP ]### 
  version   = 4
  ihl       = 5
  tos       = 0x0
  len       = 92
  id        = 1
  flags     = 
  frag      = 0
  ttl       = 30
  proto     = icmp
  chksum    = 0xb2a0
  src       = 18.191.205.48
  dst       = 10.0.0.17
  \options   \
###[ ICMP ]### 
     type      = echo-reply
     code      = 0
     chksum    = 0x70
     id        = 0x0
     seq       = 0x0
     unused    = ''
###[ Raw ]### 
        load      = '\\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x02X\x00\x00\x02X\x08\x06\x00\x00\x00\\xbef\\x98\\xdc\x00\x00\x00\\xc5zTXtRaw profile type exif\x00\x00'
```
You see it too? Let's "zoom-in" onto `[Raw].load`
```py
>>> response[Raw].load
b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x02X\x00\x00\x02X\x08\x06\x00\x00\x00\xbef\x98\xdc\x00\x00\x00\xc5zTXtRaw profile type exif\x00\x00'
```
You see it now? `PNG`! It's a png file being transmitted to us in the `Data`
(`Raw`) field of ping requests!

But how do we know when to stop?
What I did is just sent the packets until 10000, until there was no `Data` field
on one of the packets, and just like so I came to a conclusion that the packet
amount is exactly `3570`.

Now all it's left to do is to write a python script to send all the pings, and
save them into a file.

To save some time and make the script more simple, I did all the pings in
parallel.

Here is the solve script: ([solve.py](solve.py))
```py
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
```

Here is the output image:

![pong.png](pong.png)

So the flag is `bctf{pL3a$3_$t0p_p1nG1ng_M3}`
