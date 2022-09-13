# `pg_netstat`

---

**Source Code**: <a href="https://github.com/supabase/pg_netstat" target="_blank">https://github.com/supabase/pg_netstat</a>

---

### Overview

`pg_netstat` monitors your PostgreSQL database network traffic.

This extension runs a background worker to capture network packets on the Postgres port, and provides realtime network stats data by a view `pg_netstat`. It uses [libpcap](https://www.tcpdump.org/manpages/pcap.3pcap.html) to capture packets and aggreates with user-specified interval.

The `pg_netstat` view can contain at most **60** history rows and discards the oldest rows when it is full, so choose your interval wisely.

### Usage

You can query realtime network stats through the `pg_netstat` view.

```sql
select * from pg_netstat;
```

Query result is like below:

<img width="1224" alt="image" src="https://user-images.githubusercontent.com/19306324/185877241-2fe2f1cd-193b-4334-bf22-d0fd6f95dfa3.png">


### Installation

**Prerequisites**

- Before install this extension, you need to give network packet capture permission to Postgres binary. For example,

  ```
  sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/pgsql/bin/postgres
  ```

- `libpcap` library should be installed too, for example,

   ```
   sudo apt-get install libpcap-dev
   ```

After that, we can then start the installation. Download this repo and set up [`pgx`](https://github.com/tcdi/pgx):

```
cargo install cargo-pgx
```

After pgx is set up, use below command to build the extension package:

```
cargo pgx package --pg-config ~/.pgx/14.5/pgx-install/bin/pg_config
```

The extension is located at path `./target/release/pg_netstat-pg14`. For more information, please visit [pgx site](https://github.com/tcdi/pgx).

Change `postgresql.conf` to enable below line:

```
shared_preload_libraries = 'pg_netstat' # (change requires restart)
```

Restart the server and install extension in database:

```sql
create extension pg_netstat;

-- check everything is working
select * from pg_netstat;
```

### Configuration

Below are the configurations you can put in `postgresql.conf` file:

1. `pg_netstat.device` - Network device name to capture packets from, default is auto detect
2. `pg_netstat.interval` - How often network packets to be collected (in seconds), default is `10`
3. `pg_netstat.packet_wait_time` - How long to wait for network packets to be deliverd to collector (in seconds), default is `5`
4. `pg_netstat.pcap_buffer_size` - pcap setting for buffer size (in bytes), default is `1000000`
5. `pg_netstat.pcap_snaplen` - pcap setting for snapshot length (in bytes), default is `96`
6. `pg_netstat.pcap_timeout` - pcap setting for packet buffer timeout (in milliseconds), default is `1000`

You can list network device name by running `ifconfig` command. For example, device name for 'localhost' is `lo`. By default, it uses the first device that is not a `loopback` network interface.

The most useful config is `pg_netstat.interval`, which defines the stats collection frequency. Its change can be reloaded from config file by using `pg_ctl` command:

```
pg_ctl reload -D /path/to/pg-data
```

All the others settings are at low level and you probably don't want to change them. For all the `pcap_*` settings, see details at https://www.tcpdump.org/manpages/pcap.3pcap.html.

### Caveats & Limitations

- Windows is not supported, that limitation inherits from `pgx`.
- Currently only supports PostgreSQL v14, if you need other versions supported please [raise an issue](https://github.com/supabase/pg_netstat/issues).
- Only one network device can be specified to capture packets from.
- Replication haven't tested yet, use at your own risk.

### Contribution

All contributions, feature requests, bug report or ideas are welcomed.

### License

[Apache License Version 2.0](./LICENSE)

