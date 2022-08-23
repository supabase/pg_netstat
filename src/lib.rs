use pcap::{Active, Capture, Device, Direction};
use pgx::bgworkers::*;
use pgx::*;
use std::collections::VecDeque;
use std::iter::Iterator;
use std::sync::Mutex;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

pg_module_magic!();

extension_sql_file!("../sql/bootstrap.sql", bootstrap);
extension_sql_file!("../sql/finalize.sql", finalize);

struct Config {
    interval: i32,
    packet_wait_time: i32,
    pcap_buffer_size: i32,
    pcap_snaplen: i32,
    pcap_timeout: i32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            interval: 10,
            packet_wait_time: 5,
            pcap_buffer_size: 1_000_000,
            pcap_snaplen: 96,
            pcap_timeout: 1000,
        }
    }
}

struct ConfigLoader {
    interval_guc: GucSetting<i32>,
    packet_wait_time_guc: GucSetting<i32>,
    pcap_buffer_size_guc: GucSetting<i32>,
    pcap_snaplen_guc: GucSetting<i32>,
    pcap_timeout_guc: GucSetting<i32>,
}

impl ConfigLoader {
    fn new() -> Self {
        let cfg = Config::default();
        let ret = ConfigLoader {
            interval_guc: GucSetting::new(cfg.interval),
            packet_wait_time_guc: GucSetting::new(cfg.packet_wait_time),
            pcap_buffer_size_guc: GucSetting::new(cfg.pcap_buffer_size),
            pcap_snaplen_guc: GucSetting::new(cfg.pcap_snaplen),
            pcap_timeout_guc: GucSetting::new(cfg.pcap_timeout),
        };

        GucRegistry::define_int_guc(
            "pg_netstat.interval",
            "network packets collection interval",
            "How often network packets to be collected (in seconds)",
            &ret.interval_guc,
            1,
            900_000,
            GucContext::Sighup,
        );
        GucRegistry::define_int_guc(
            "pg_netstat.packet_wait_time",
            "network packets delivery wait time",
            "How long to wait for network packets to be deliverd to collector (in seconds)",
            &ret.packet_wait_time_guc,
            1,
            10,
            GucContext::Sighup,
        );
        GucRegistry::define_int_guc(
                "pg_netstat.pcap_buffer_size",
                "pcap buffer size",
                "pcap setting for buffer size (in bytes), see details: https://www.tcpdump.org/manpages/pcap.3pcap.html",
                &ret.pcap_buffer_size_guc,
                131_070,
                90_000_000,
                GucContext::Sighup,
            );
        GucRegistry::define_int_guc(
                "pg_netstat.pcap_snaplen",
                "pcap snapshot length",
                "pcap setting for snapshot length (in bytes), see details: https://www.tcpdump.org/manpages/pcap.3pcap.html",
                &ret.pcap_snaplen_guc,
                96,
                65535,
                GucContext::Sighup,
            );
        GucRegistry::define_int_guc(
                "pg_netstat.pcap_timeout",
                "pcap packet buffer timeout",
                "pcap setting for packet buffer timeout (in milliseconds), see details: https://www.tcpdump.org/manpages/pcap.3pcap.html",
                &ret.pcap_timeout_guc,
                1,
                30_000,
                GucContext::Sighup,
            );
        ret
    }

    fn load_config(&self) -> Config {
        Config {
            interval: self.interval_guc.get(),
            packet_wait_time: self.packet_wait_time_guc.get(),
            pcap_buffer_size: self.pcap_buffer_size_guc.get(),
            pcap_snaplen: self.pcap_snaplen_guc.get(),
            pcap_timeout: self.pcap_timeout_guc.get(),
        }
    }
}

#[inline]
fn get_current_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("get system time failed")
        .as_secs() as i64
}

#[derive(Debug, Default, Copy, Clone)]
struct Slot {
    ts: i64,
    packets_in: i64,
    packets_out: i64,
    bytes_in: i64,
    bytes_out: i64,
    created_at: i64,
}

impl Slot {
    fn new(ts: i64) -> Self {
        let mut ret = Slot::default();
        ret.ts = ts;
        ret
    }

    fn to_row_tuple(&self, interval: i64) -> (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) {
        (
            self.ts,
            self.packets_in,
            self.packets_out,
            self.packets_in / interval,  // packets_in_speed
            self.packets_out / interval, // packets_out_speed
            self.bytes_in,
            self.bytes_out,
            self.bytes_in / interval,  // bytes_in_speed
            self.bytes_out / interval, // bytes_out_speed
            self.created_at,
        )
    }
}

unsafe impl PGXSharedMemory for Slot {}

#[derive(Default, Clone)]
struct Stats {
    interval: i64,
    write_at: usize,
    slots: heapless::Vec<Slot, 60>, // fixed capacity Vec
}

impl Stats {
    fn write(&mut self, mut slot: Slot) {
        slot.created_at = get_current_ts();

        if self.slots.is_full() {
            let write_at = self.write_at;
            self.slots[write_at] = slot;
        } else {
            let _ = self.slots.push(slot);
        }
        self.write_at = (self.write_at + 1) % self.slots.capacity();
    }

    fn reset(&mut self, cfg: &Config) {
        self.interval = cfg.interval as i64;
        self.write_at = 0;
        self.slots.clear();
    }
}

unsafe impl PGXSharedMemory for Stats {}

static STATS: PgLwLock<Stats> = PgLwLock::new();

#[pg_guard]
pub extern "C" fn _PG_init() {
    pg_shmem_init!(STATS);

    BackgroundWorkerBuilder::new("pg_netstat background worker")
        .set_function("bg_worker_main")
        .set_library("pg_netstat")
        .set_start_time(BgWorkerStartTime::ConsistentState)
        .enable_shmem_access(None)
        .enable_spi_access()
        .load();
}

#[pg_extern]
fn netstat() -> impl Iterator<
    Item = (
        name!(ts, i64),
        name!(packets_in, i64),
        name!(packets_out, i64),
        name!(packets_in_speed, i64),
        name!(packets_out_speed, i64),
        name!(bytes_in, i64),
        name!(bytes_out, i64),
        name!(bytes_in_speed, i64),
        name!(bytes_out_speed, i64),
        name!(created_at, i64),
    ),
> {
    let stats = STATS.share();
    stats
        .slots
        .iter()
        .map(|s| s.to_row_tuple(stats.interval))
        .collect::<Vec<_>>()
        .into_iter()
}

#[derive(Debug)]
struct Counter {
    ts_start: i64,
    slots: VecDeque<Slot>,
}

impl Counter {
    fn save_slot(&mut self) {
        assert!(self.slots.len() > 1);

        let slot = self.slots.pop_front().unwrap();
        let mut stats = STATS.exclusive();
        stats.write(slot);

        //log!("{}", format!("**==>save slot {:?}", slot));

        self.ts_start = self.slots.front().unwrap().ts;
    }

    fn reset(&mut self) {
        self.ts_start = get_current_ts();
        self.slots.clear();
    }
}

impl Default for Counter {
    fn default() -> Self {
        Counter {
            ts_start: get_current_ts(),
            slots: VecDeque::new(),
        }
    }
}

fn create_capture(
    device_name: &str,
    cfg: &Config,
    port: i32,
    direction: Direction,
) -> Capture<Active> {
    let dir = match direction {
        Direction::In => "dst",
        Direction::Out => "src",
        _ => unreachable!(),
    };
    let filter = format!("tcp and {} port {}", dir, port);
    let mut cap = Capture::from_device(device_name)
        .expect("create capture failed")
        .buffer_size(cfg.pcap_buffer_size)
        .snaplen(cfg.pcap_snaplen)
        .timeout(cfg.pcap_timeout)
        .open()
        .expect("open capture failed")
        .setnonblock()
        .expect("set nonblock mode failed");
    cap.filter(&filter, true)
        .expect("apply packet filter failed");
    cap
}

fn collect_capture(
    cap: &mut Capture<Active>,
    cntr: &mut Counter,
    interval: i32,
    direction: Direction,
) {
    while let Ok(packet) = cap.next_packet() {
        //log!("{}", format!("==received {:?} packet {:?}", direction, packet.header));
        let hdr = &packet.header;
        let pkt_ts = hdr.ts.tv_sec;
        assert!(pkt_ts >= cntr.ts_start);
        let idx = ((pkt_ts - cntr.ts_start) / interval as i64) as usize;
        match direction {
            Direction::In => {
                cntr.slots[idx].packets_in += 1;
                cntr.slots[idx].bytes_in += hdr.len as i64;
            }
            Direction::Out => {
                cntr.slots[idx].packets_out += 1;
                cntr.slots[idx].bytes_out += hdr.len as i64;
            }
            _ => unreachable!(),
        }
    }
}

#[pg_guard]
#[no_mangle]
pub extern "C" fn bg_worker_main(_arg: pg_sys::Datum) {
    // these are the signals we want to receive.  If we don't attach the SIGTERM handler, then
    // we'll never be able to exit via an external notification
    BackgroundWorker::attach_signal_handlers(SignalWakeFlags::SIGHUP | SignalWakeFlags::SIGTERM);

    // we want to be able to use SPI against the specified database (postgres), as the superuser which
    // did the initdb. You can specify a specific user with Some("my_user")
    BackgroundWorker::connect_worker_to_spi(Some("postgres"), None);

    let worker_name = BackgroundWorker::get_name();
    let cfg_loader = ConfigLoader::new();
    let mut cfg = cfg_loader.load_config();

    // get device name
    //let device_name = Some("ens4");
    let device_name = Some("lo");
    //let device_name: Option<String> = None;
    let device_name = if device_name.is_none() {
        let device = Device::lookup()
            .expect("device lookup failed")
            .expect("no device availabe");
        device.name.to_owned()
    } else {
        device_name.unwrap().to_string()
    };

    // get port number from settings
    let port = {
        let port = Mutex::new(0i32);
        BackgroundWorker::transaction(|| {
            let port_setting = Spi::get_one::<String>("SELECT current_setting('port')")
                .expect("query port failed")
                .parse()
                .unwrap();
            *port.lock().unwrap() = port_setting;
        });
        let ret = *port.lock().unwrap();
        ret
    };

    STATS.exclusive().reset(&cfg);

    let mut cap_in = create_capture(device_name.as_str(), &cfg, port, Direction::In);
    let mut cap_out = create_capture(device_name.as_str(), &cfg, port, Direction::Out);
    let mut cntr = Counter::default();

    log!(
        "{} started capture on device \"{}\" port {}",
        worker_name,
        device_name,
        port
    );

    // wake up every second or if we received a SIGTERM
    while BackgroundWorker::wait_latch(Some(Duration::from_secs(1))) {
        if BackgroundWorker::sighup_received() {
            // on SIGHUP config is reloaded, need to reset counter and stats
            cfg = cfg_loader.load_config();
            cntr.reset();
            STATS.exclusive().reset(&cfg);
        }

        let now = get_current_ts();
        let span = ((now - cntr.ts_start) / cfg.interval as i64 + 1) as usize;
        while span > cntr.slots.len() {
            let last_ts = cntr
                .slots
                .back()
                .map_or(cntr.ts_start, |s| s.ts + cfg.interval as i64);
            cntr.slots.push_back(Slot::new(last_ts));
        }

        collect_capture(&mut cap_in, &mut cntr, cfg.interval, Direction::In);
        collect_capture(&mut cap_out, &mut cntr, cfg.interval, Direction::Out);

        // add a bit wait time for delayed packets to be delivered
        while now > cntr.ts_start + (cfg.interval + cfg.packet_wait_time) as i64 {
            cntr.save_slot();
        }
    }

    log!("{} stopped", worker_name);
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgx::*;

    #[pg_test]
    fn test_pg_netstat() {
        todo!();
    }
}

#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}
