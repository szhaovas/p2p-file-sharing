# Reliable P2P File-Sharing Program

A BitTorrent-like P2P file sharing program, with reliable sliding-window algorithm and congestion control implemented on top of UDP.

## Overview
The `main()` entry point is in `peer.c`, which initializes a peer and runs a `select()` loop to listen for and executes user commands, and monitor inbound traffic.

Anything related to packets are defined in `packet.[h|c]`, which exposes interfaces to send, parse, validate, and dispatch different kinds of packets. Packet format and construction are purposefully hidden from the foreign callers.

Borrowing BitTorrent terminologies, we call the uploader a *seeder*, and the downloader a *leecher*. Seeder and leecher code can be found in `peer-seeder.[h|c]` and `peer-leecher.[h|c]`, where the seeder/leecher handles inbound packets for which they are responsible and sends replies accordingly. For example, the seeder handles `WHOHAS`, `GET` and `ACK`, and answers them with `IHAVE` and `DATA`. Flow & congestion control mechanisms are also implemented there, while parameters and helper functions common to both the seeder and the leecher are defined in `peer-reliable.[h|c]`.

Linked lists (`linked-list.[h|c]`) form the core data structure, storing chunk and peer information. We should note, however, that hash tables would be the most natural choice here, since both the chunks and the peers suggest natural hashing functions. Although due to time constraints we did not choose to do so, but it should be easy to implement a separate-chaining hash table data structure, building on our already well-tested linked list code.


## General Control Flow and Robustness
Upon receiving a GET command from the user, the main program filters out the chunks that the operating leecher already owns. The leecher then floods the network with WHOHAS packets containing the hashes of the missing chunks, stored in `pending_chunks`. The leecher keeps a list of peers who might become future seeders, called `seeder_waitlist`. Whenever an IHAVE packet is received from a new peer X, the leecher adds X to the waitlist, and appends the promised chunks to X's download queue.

Once all IHAVE replies have been received, the leecher promote `max_conn` number of peers to the `active_peers` list, and for each seeder the leccher initiates one download--the head of the download queue--by sending the seeder a GET packet. If unable to gather IHAVE replies for all missing chunks within a reasonable amount of time, the leecher reports a fatal error and forfeits the current download attempt.

The seeder and the leecher now exchange DATA and ACK packets (see Reliability and Flow Control). If party **A** does not hear from party **B** within a reasonable number of timeout & retransmission attempts, then **A** assumes that **B** is no longer reachable, and transfers the chunks in B's download queue back to `pending_chunks`. (Once **A** finished the downloads from all seeders, it tries downloading the accumulated failed chunks by resending WHOHAS and repeating the whole process.)

Once the leecher finishes downloading a chunk, it checksums the data by recomputing the hash. If the hash matches, it writes the chunk to the appropriate place in the output `data_file`; otherwise, it resends a GET packet to the same seedeer. The leecher marks this chunk as owned, with pointer to `data_file` so that it will be able to seed this chunk to other peers when requested.

When `select()` returns from its periodic timeout, the functions `seeder_timeout()` and `leecher_timeout()` are run to check activity of the connected peers to, e.g. retransmit unacknowledged data or handle a stagnant, broken connection.


## Reliability and Flow Control

We implemented a sliding window algorithm to ensure reliable, in-order delivery of packets.
- For simplicity, the leecher does not keep any receiving window, and instead uses the same ACK policy as in a stop and wait ARQ (also equivalent to a Go-Back-N ARQ). That is, the leecher does not buffer out-of-order packets, and sends cumulative ACKs.

- The seeder keeps a variable-size window (see section Congestion Control) to pace itself.


## Congestion Control

We implemented the following congestion control mechanisms.
- The seeder maintains a list of leechers, and associates a congestion window (cw_size) and ssthresh to each of them. Therefore, there is not an aggregate congestion control for all the data going in and out of the seeder, but an independent congestion control for each connection. 
- At the start of the transmission, congestion window is set to be 1 and ssthresh 64.
- Congestion window is incremented by 1 upon each correct ACK before reaching ssthresh, and by 1/congestion_window upon each correct ACK after reaching ssthresh.
- If a duplicate ACK occurs, ssthresh is set to half of the old congestion window (no smaller than 1), and congestion window is reset to the new ssthresh.
- If a timeout occurs, ssthresh is set to half of the old congestion window (no smaller than 1), and congestion window is reset to 1.

Notes.
- windowsize-peer-<peer-id>.txt is created at the working directory. If you cannot find it, please go to peer.c line 336 to change the directory.
- A windowsize-peer-<peer-id>.txt is created for each peer, whether it is the sender or leecher; this can result in some windowsize-peer-<peer-id>.txt files being empty (if the peer never seeds).
- We set no upper bound for the congestion window during the AIMD phase.


## Other Design Choices

We assume the the other peers are well-behaved. For example, when the checksum of the downloaded chunk does not match with the desired hash, we assume that it was due to transmission errors, not because the seeder's original data was corrupted. Therefore, in those places we do not place a limit on the number of retries, and hope that the download will eventually succeed by retransmissions.

## Test Cases

We have only tested our code on the two-peer topology suggested in the handout. However, we have tested reliability by deterministically dropping the $k$-th packet out of every $n$ packets, and randomly dropping a packet with probability $p < 0.2$.
