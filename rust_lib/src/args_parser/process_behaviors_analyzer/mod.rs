use std::time::Duration;

use procfs::FromRead;
use sysinfo::System;
use colored::*;
use system_uptime::get_os_uptime_duration;

pub struct ProcessBehaviorsAnalyzer {
    sys: System,
    exceptions: Vec<String>
}

#[allow(clippy::new_without_default)]
impl ProcessBehaviorsAnalyzer {
    pub fn new() -> Self {
        Self {
            sys: System::new_all(),
            exceptions: vec![
                String::from("electron"),
            ]
        }
    }

    pub fn analyze(&mut self) {
        self.sys.refresh_all();

        // for cpu in self.sys.cpus() {
        //     let usage = cpu.cpu_usage();
        //     println!("{:.2}%", usage);
        // }

        for (pid, proc) in self.sys.processes() {
            let procfs = match procfs::process::Process::new(pid.as_u32() as i32) {
                Ok(procfs) => procfs,
                Err(_) => continue,
            };
            let proc_name = proc.name().to_string_lossy();
            let stat1 = match procfs.stat() {
                Ok(stat) => stat,
                Err(e) => {
                    eprintln!("Couldn't get the stats of process {pid}, {proc_name}\nError: {e}");
                    continue;
                }
            };
            std::thread::sleep(Duration::from_millis(500));
            let stat2 = match procfs.stat() {
                Ok(stat) => stat,
                Err(e) => {
                    eprintln!("Couldn't get the stats of process {pid}, {proc_name}\nError: {e}");
                    continue;
                }
            };

            let total_time = (stat2.utime + stat2.stime) - (stat1.utime + stat1.stime); // 645 + 407 = 1052 clock ticks
            let clock_ticks_per_sec = 100; // usually 100 on Linux
            let cpu_usage = (total_time / clock_ticks_per_sec) as f64 * 2.0 * 100.0;

            let procfs_status = match procfs.status() {
                Ok(status) => status,
                Err(e) => {
                    eprintln!("Couldn't get procfs status\nError: {e}");
                    continue;
                }
            };
            let vmrss = match procfs_status.vmrss {
                Some(vmrss) => vmrss,
                None => continue
            };
            let meminfo = match procfs::Meminfo::from_file("/proc/meminfo") {
                Ok(meminfo) => meminfo,
                Err(e) => {
                    eprintln!("Couldn't read /proc/meminfo\nError: {e}");
                    continue;
                }
            };
            let total_mem = meminfo.mem_total * 1024;

            let mem_usage = (vmrss as f64 / total_mem as f64) * 100.0;

            if cpu_usage >= 20.0 || mem_usage >= 20.0 {
                self.exceptions.iter().for_each(|exception| {
                    if proc_name.to_ascii_lowercase() != **exception {
                        println!("[{}, {}]\nCPU USAGE: {:.2}%\nMEMORY USAGE: {:.2}%", pid.to_string().bold(), proc_name, cpu_usage, mem_usage);
                    }
                });
            }
        }
    }
}
