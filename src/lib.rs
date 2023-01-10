#![allow(clippy::type_complexity)]

use heapless::{String as HLString, Vec as HLVec};
use pcap::{Active, Capture, Device, Direction, IfFlags};
use pgx::{bgworkers::*, guc::*, lwlock::PgLwLock, prelude::*, shmem::*};
use std::collections::VecDeque;
use std::iter::Iterator;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

pgx::pg_module_magic!();

extension_sql_file!("../sql/bootstrap.sql", bootstrap);
extension_sql_file!("../sql/finalize.sql", finalize);

// maximum devices to capture
const MAX_DEVICES: usize = 4;

// maximum stats capture slots
const MAX_SLOTS: usize = 60;

struct Config {
    devices: Option<String>,
    devices_final: Vec<String>, // finalized device names, for internal use
    interval: i32,
    capture_loopback: bool,
    packet_wait_time: i32,
    pcap_buffer_size: i32,
    pcap_snaplen: i32,
    pcap_timeout: i32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            devices: None,
            devices_final: Vec::new(),
            interval: 10,
            capture_loopback: false,
            packet_wait_time: 5,
            pcap_buffer_size: 1_000_000,
            pcap_snaplen: 96,
            pcap_timeout: 1000,
        }
    }
}

struct ConfigLoader {
    devices_guc: GucSetting<Option<&'static str>>,
    interval_guc: GucSetting<i32>,
    capture_loopback_guc: GucSetting<bool>,
    packet_wait_time_guc: GucSetting<i32>,
    pcap_buffer_size_guc: GucSetting<i32>,
    pcap_snaplen_guc: GucSetting<i32>,
    pcap_timeout_guc: GucSetting<i32>,
}

impl ConfigLoader {
    fn new() -> Self {
        let cfg = Config::default();
        let ret = ConfigLoader {
            devices_guc: GucSetting::new(None),
            interval_guc: GucSetting::new(cfg.interval),
            capture_loopback_guc: GucSetting::new(cfg.capture_loopback),
            packet_wait_time_guc: GucSetting::new(cfg.packet_wait_time),
            pcap_buffer_size_guc: GucSetting::new(cfg.pcap_buffer_size),
            pcap_snaplen_guc: GucSetting::new(cfg.pcap_snaplen),
            pcap_timeout_guc: GucSetting::new(cfg.pcap_timeout),
        };

        GucRegistry::define_string_guc(
            "pg_netstat.devices",
            "network device names",
            "Network device names to capture packets from, delimited by comma, maximum 4 devices",
            &ret.devices_guc,
            GucContext::Sighup,
        );
        GucRegistry::define_int_guc(
            "pg_netstat.interval",
            "network packets collection interval",
            "How often network packets to be collected (in seconds)",
            &ret.interval_guc,
            1,
            900_000,
            GucContext::Sighup,
        );
        GucRegistry::define_bool_guc(
            "pg_netstat.capture_loopback",
            "capture on loopback device",
            "Whether capture packets on loopback device",
            &ret.capture_loopback_guc,
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
            devices: self.devices_guc.get(),
            devices_final: Vec::new(),
            interval: self.interval_guc.get(),
            capture_loopback: self.capture_loopback_guc.get(),
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
        Slot {
            ts,
            ..Default::default()
        }
    }

    fn as_row_tuple(
        &self,
        device: &str,
        interval: i64,
    ) -> (String, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) {
        (
            device.to_owned(),
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

    // network device names, device name size limit is 16
    devices: HLVec<HLString<16>, MAX_DEVICES>,

    // capture slots, maximum 60 slots per device
    slots: HLVec<HLVec<Slot, MAX_SLOTS>, MAX_DEVICES>,
}

impl Stats {
    fn write(&mut self, mut slots: Vec<Slot>) {
        assert_eq!(self.slots.len(), slots.len());

        let now = get_current_ts();

        for tgt in self.slots.iter_mut() {
            let mut slot = slots.remove(0);

            slot.created_at = now;

            if tgt.is_full() {
                tgt[self.write_at] = slot;
            } else {
                let _ = tgt.push(slot);
            }
        }

        self.write_at = (self.write_at + 1) % MAX_SLOTS;
    }

    fn reset(&mut self, cfg: &Config) {
        self.interval = cfg.interval as i64;
        self.write_at = 0;

        self.devices.clear();
        self.slots.clear();
        for device in cfg.devices_final.iter() {
            self.devices
                .push(HLString::from_str(device).unwrap())
                .unwrap();
            self.slots.push(HLVec::new()).unwrap();
        }
    }
}

unsafe impl PGXSharedMemory for Stats {}

static STATS: PgLwLock<Stats> = PgLwLock::new();

#[pg_guard]
pub extern "C" fn _PG_init() {
    pgx::pg_shmem_init!(STATS);

    BackgroundWorkerBuilder::new("pg_netstat background worker")
        .set_function("bg_worker_main")
        .set_library("pg_netstat")
        .set_start_time(BgWorkerStartTime::ConsistentState)
        .enable_shmem_access(None)
        .enable_spi_access()
        .load();
}

#[pg_extern]
fn netstat() -> TableIterator<
    'static,
    (
        name!(device, String),
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
    let mut data = Vec::new();

    for (idx, device) in stats.devices.iter().enumerate() {
        data.extend(
            stats.slots[idx]
                .iter()
                .map(|s| s.as_row_tuple(device, stats.interval))
                .collect::<Vec<_>>()
                .into_iter(),
        );
    }

    TableIterator::new(data.into_iter())
}

#[derive(Debug)]
struct Counter {
    ts_start: i64,
    slots: Vec<VecDeque<Slot>>,
}

impl Counter {
    fn new(device_cnt: usize) -> Self {
        Self {
            ts_start: get_current_ts(),
            slots: vec![VecDeque::new(); device_cnt],
        }
    }

    fn save_slot(&mut self) {
        let slots = self
            .slots
            .iter_mut()
            .map(|slots| slots.pop_front().unwrap())
            .collect();
        //log!("{}", format!("**==>save slots {:?}", slots));

        let mut stats = STATS.exclusive();
        stats.write(slots);

        self.ts_start = self.slots[0].front().unwrap().ts;
    }

    fn reset(&mut self) {
        self.ts_start = get_current_ts();
        for slots in self.slots.iter_mut() {
            slots.clear();
        }
    }
}

// find loopback device
fn find_loopback() -> String {
    let devices = Device::list().expect("list device failed");
    for device in devices {
        if device.flags.if_flags.intersects(IfFlags::LOOPBACK) {
            return device.name;
        }
    }
    panic!("cannot find loopback device")
}

// create a packet capture
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
    device_idx: usize,
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
        let slots = &mut cntr.slots[device_idx];
        match direction {
            Direction::In => {
                slots[idx].packets_in += 1;
                slots[idx].bytes_in += hdr.len as i64;
            }
            Direction::Out => {
                slots[idx].packets_out += 1;
                slots[idx].bytes_out += hdr.len as i64;
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

    // get device names string
    let mut device_names: String = match cfg.devices {
        Some(ref devices) => devices.clone(),
        None => {
            let device = Device::lookup()
                .expect("device lookup failed")
                .expect("no device availabe");
            device.name
        }
    };

    // if need capture loopback, find its name and append to device names string
    if cfg.capture_loopback {
        let loopback = find_loopback();
        device_names.push_str(&format!(",{}", loopback));
    }

    // finalize device names and save back to config
    cfg.devices_final = device_names
        .split(',')
        .map(|s| s.trim().to_owned())
        .collect();
    cfg.devices_final.dedup();
    if cfg.devices_final.len() > MAX_DEVICES {
        panic!(
            "can only capture {} devices, but {} specified",
            MAX_DEVICES,
            cfg.devices_final.len()
        );
    }

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

    let mut cntr = Counter::new(cfg.devices_final.len());
    let mut caps: Vec<(Capture<Active>, Capture<Active>)> = Vec::new();

    for device in &cfg.devices_final {
        let cap_in = create_capture(device, &cfg, port, Direction::In);
        let cap_out = create_capture(device, &cfg, port, Direction::Out);
        caps.push((cap_in, cap_out));
    }

    log!(
        "{} started capture on device {:?} port {}",
        worker_name,
        cfg.devices_final,
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
        let slot_idx = ((now - cntr.ts_start) / cfg.interval as i64 + 1) as usize;
        while slot_idx > cntr.slots[0].len() {
            let last_ts = cntr.slots[0]
                .back()
                .map_or(cntr.ts_start, |s| s.ts + cfg.interval as i64);
            for slots in cntr.slots.iter_mut() {
                slots.push_back(Slot::new(last_ts));
            }
        }

        for (device_idx, cap) in caps.iter_mut().enumerate() {
            collect_capture(
                &mut cap.0,
                device_idx,
                &mut cntr,
                cfg.interval,
                Direction::In,
            );
            collect_capture(
                &mut cap.1,
                device_idx,
                &mut cntr,
                cfg.interval,
                Direction::Out,
            );
        }

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
