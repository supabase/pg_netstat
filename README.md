# `pg_netstat`

---

**Documentation**: <a href="https://supabase.github.io/pg_netstat" target="_blank">https://supabase.github.io/pg_netstat</a>

**Source Code**: <a href="https://github.com/supabase/pg_netstat" target="_blank">https://github.com/supabase/pg_netstat</a>

---

### Overview

`pg_netstat` monitors your PostgreSQL database network traffic.

This extension runs a background worker to capture network packets on the Postgres port, and provides realtime network stats data by a view `pg_netstat`. It uses [libpcap](https://www.tcpdump.org/manpages/pcap.3pcap.html) to do packets capturing and aggreates with user-specified interval.

### Usage

You can query realtime network stats through querying `pg_netstat` view.

```sql
select * from pg_netstat;
```

Query result is like below:

<img width="1224" alt="image" src="https://user-images.githubusercontent.com/19306324/185877241-2fe2f1cd-193b-4334-bf22-d0fd6f95dfa3.png">


### Installation

To install this extension, you need to give network packet capture permission to Postgres binary. For example,

```
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/pgsql/bin/postgres
```

TODO

### Configuration

Below are the configurations you can put in `postgresql.conf` file:

1. `pg_netstat.interval` - How often network packets to be collected (in seconds)
2. `pg_netstat.packet_wait_time` - How long to wait for network packets to be deliverd to collector (in seconds)
3. `pg_netstat.pcap_buffer_size` - pcap setting for buffer size (in bytes)
4. `pg_netstat.pcap_snaplen` - pcap setting for snapshot length (in bytes)
5. `pg_netstat.pcap_timeout` - pcap setting for packet buffer timeout (in milliseconds)

The most useful config is `interval`, which defines the stats collection frequency and all the others are low level and you probably don't want to change. For all the `pcap_*` settings, see details at https://www.tcpdump.org/manpages/pcap.3pcap.html.

Below is an example:

```
pg_netstat.interval = 10
pg_netstat.packet_wait_time = 5
pg_netstat.pcap_buffer_size = 1000000
pg_netstat.pcap_snaplen = 96
pg_netstat.pcap_timeout = 1000
```
