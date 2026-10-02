//! Direct-source calendar regression boundary. Environment, allocation and errno
//! are supplied by pinned musl. Unused ASCII locale projections are stubbed.
//! Timezone parsing, mappings, raw syscalls and conversions are the owned source;
//! secure startup policy and locale formatting require their separate callers.
#![feature(linkage)]
#![allow(dead_code)]
macro_rules! static_archive_member { ($module:ident {$($item:item)*}) => {$($item)*}; }
mod errno {
    unsafe extern "C" { fn __errno_location() -> *mut i32; }
    pub unsafe fn set_errno(value:i32) { unsafe { *__errno_location()=value; } }
    pub fn get() -> i32 { unsafe { *__errno_location() } }
}
mod environment {
    unsafe extern "C" { #[link_name="getenv"] fn c_getenv(name:*const core::ffi::c_char)->*mut core::ffi::c_char; }
    pub unsafe fn getenv(name:*const core::ffi::c_char)->*mut core::ffi::c_char { unsafe {c_getenv(name)} }
}
mod allocator {
    unsafe extern "C" { fn malloc(size:usize)->*mut core::ffi::c_void; }
    pub unsafe fn allocate_internal(size:usize)->*mut core::ffi::c_void { unsafe {malloc(size)} }
}
mod startup_security { pub fn is_secure()->bool {false} }
mod locale_objects {
    pub fn fixed_c_locale()->*mut core::ffi::c_void {core::ptr::null_mut()}
    pub unsafe fn nl_langinfo_l(_:i32,_:*mut core::ffi::c_void)->*const core::ffi::c_char {c"unused".as_ptr()}
}
mod raw_syscall {
    pub unsafe fn syscall6(n:i64,a:i64,b:i64,c:i64,d:i64,e:i64,f:i64)->i64 {
        let result;
        unsafe { core::arch::asm!("syscall",inlateout("rax") n=>result,
            in("rdi") a,in("rsi") b,in("rdx") c,in("r10") d,in("r8") e,in("r9") f,
            lateout("rcx") _,lateout("r11") _,options(nostack)); }
        result
    }
    pub unsafe fn syscall1(n:i64,a:i64)->i64 {unsafe{syscall6(n,a,0,0,0,0,0)}}
    pub unsafe fn syscall2(n:i64,a:i64,b:i64)->i64 {unsafe{syscall6(n,a,b,0,0,0,0)}}
    pub unsafe fn syscall3(n:i64,a:i64,b:i64,c:i64)->i64 {unsafe{syscall6(n,a,b,c,0,0,0)}}
    pub unsafe fn syscall4(n:i64,a:i64,b:i64,c:i64,d:i64)->i64 {unsafe{syscall6(n,a,b,c,d,0,0)}}
}
#[path="../../libc/src/c_abi/x86_64/timegm.rs"] mod timegm;
#[path="../../libc/src/c_abi/x86_64/gmtime_r.rs"] mod gmtime_r;
#[path="../../libc/src/c_abi/x86_64/owned_timezone.rs"] mod owned_timezone;
#[path="../../libc/src/c_abi/x86_64/owned_calendar.rs"] mod owned_calendar;
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn record(result:i64,value:&timegm::Tm)->String {
    assert!(!value.utc_name.is_null(),"successful conversion publishes a zone name");
    let name=unsafe {std::ffi::CStr::from_ptr(value.utc_name)}.to_str().unwrap();
    format!("{result} {} {} {} {} {} {} {} {} {} {} {name} {}\n",value.year,value.month,
        value.month_day,value.hours,value.minutes,value.seconds,value.week_day,value.year_day,
        value.daylight_saving,value.utc_offset,errno::get())
}
fn compare(zone:&str,mode:&str,arguments:&[i64]) {
    unsafe {if zone=="-" {std::env::remove_var("TZ")} else {std::env::set_var("TZ",zone)}};
    owned_timezone::tzset();
    unsafe {errno::set_errno(47)};
    let mut value=owned_calendar::ZERO;
    let result=if mode=="l" {
        let seconds=arguments[0];
        assert!(!unsafe {owned_calendar::localtime_r(&seconds,&mut value)}.is_null());
        seconds
    } else {
        value.year=arguments[0] as i32;value.month=arguments[1] as i32;value.month_day=arguments[2] as i32;
        value.hours=arguments[3] as i32;value.minutes=arguments[4] as i32;value.seconds=arguments[5] as i32;
        value.daylight_saving=arguments[6] as i32;
        unsafe {owned_calendar::mktime(&mut value)}
    };
    let candidate=record(result,&value);
    let oracle=std::process::Command::new(std::env::var("TIMEZONE109_ORACLE").unwrap())
        .arg(zone).arg(mode).args(arguments.iter().map(|x|x.to_string())).output().unwrap();
    assert!(oracle.status.success(),"oracle {zone} {mode} {arguments:?}: {:?}",oracle.status);
    assert_eq!(candidate,String::from_utf8(oracle.stdout).unwrap(),"zone={zone}, mode={mode}, arguments={arguments:?}");
}
#[test]
fn selected_posix_negative_calendar_transition_and_gap_fold_match_pinned_musl() {
    let _guard=TEST_LOCK.lock().unwrap_or_else(|poison|poison.into_inner());
    for zone in ["UTC0","EST5EDT,M3.2.0/2,M11.1.0/2","AEST-10AEDT-11,M10.1.0/2,M4.1.0/3",
        "<+03>-3","NST3:30NDT2:30,J60/-2,J300/26","AAA0BBB,59/0,300/0"] {
        for seconds in [-2208988800,-1,0,951782400,1615705199,1615705200,1636264799,1636264800,
            1710053999,1710054000,1730613599,1730613600,4102444800] {compare(zone,"l",&[seconds]);}
        for dst in [-1,0,1] {
            for civil in [[121,2,14,2,30,0],[121,10,7,1,30,0],[-1,1,29,0,0,0],[-301,-13,0,-1,61,61]] {
                let mut args=civil.to_vec();args.push(dst);compare(zone,"m",&args);
            }
        }
    }
}
#[test]
fn system_zone_files_apply_real_offsets_and_keep_only_the_current_mapping() {
    let _guard=TEST_LOCK.lock().unwrap_or_else(|poison|poison.into_inner());
    let root="/workspace/.work/timezone109/zones";
    for (name,winter,summer) in [("America/New_York",-18000,-14400),("Europe/Berlin",3600,7200),
        ("Australia/Lord_Howe",39600,37800),("Pacific/Apia",50400,46800)] {
        let path=format!("{root}/{name}");
        for seconds in [-2208988800,-1,0,1609459200,1625097600,2147483647,4102444800] {compare(&path,"l",&[seconds]);}
        unsafe {std::env::set_var("TZ",&path)};owned_timezone::tzset();
        let mut tm=owned_calendar::ZERO;
        for (seconds,offset) in [(1609459200,winter),(1625097600,summer)] {
            assert!(!unsafe {owned_calendar::localtime_r(&seconds,&mut tm)}.is_null());
            assert_eq!(tm.utc_offset,offset,"required physical zone file: {name}");
            let name_address=tm.utc_name as usize;
            let maps=std::fs::read_to_string("/proc/self/maps").unwrap();
            let zone_map=maps.lines().find(|line|line.ends_with(&format!("/zones/{name}"))).expect("current zone retains its file map");
            let bounds=zone_map.split_whitespace().next().unwrap().split('-').map(|n|usize::from_str_radix(n,16).unwrap()).collect::<Vec<_>>();
            // A rule-bearing footer publishes copied process names after
            // the final explicit transition; older abbreviations remain mapped.
            let names=unsafe {core::ptr::addr_of!(owned_timezone::__tzname).read()};
            assert!((bounds[0]..bounds[1]).contains(&name_address)
                || names.iter().any(|p|p.addr()==name_address),
                "abbreviation belongs to current map or rule state: {name} {seconds}");
            assert_eq!(maps.lines().filter(|line|line.contains("/timezone109/zones/")).count(),1,"previous TZ mapping released");
        }
        for dst in [-1,0,1] {
            compare(&path,"m",&[121,2,14,2,30,0,dst]);
            compare(&path,"m",&[121,10,7,1,30,0,dst]);
        }
        compare(name,"l",&[1609459200]);compare(name,"l",&[1625097600]);
    }
    compare("Etc/UTC","l",&[-1]);
    for index in 0..20 {compare(if index%2==0 {"UTC0"} else {"<LONG_STANDARD_NAME>5<LONG_DAYLIGHT_NAME>,M3.2.0,M11.1.0"},"l",&[1615705200]);}
    unsafe {std::env::set_var("TZ","UTC0")};owned_timezone::tzset();
    assert!(!std::fs::read_to_string("/proc/self/maps").unwrap().contains("/timezone109/zones/"));
}

#[test]
fn default_system_file_and_transition_cache_refresh_preserve_civil_state() {
    let _guard=TEST_LOCK.lock().unwrap_or_else(|poison|poison.into_inner());
    compare("-","l",&[1609459200]);
    let mut tm=owned_calendar::ZERO;
    let instant=1609459200;
    assert!(!unsafe {owned_calendar::localtime_r(&instant,&mut tm)}.is_null());
    assert_eq!(tm.utc_offset,-18000,"supplied default system file must be New York");
    let path="/workspace/.work/timezone109/cache-transition.tzif";
    fn write_zone(path:&str,offset:i32) {
        let mut bytes=std::vec![0u8;44];bytes[..4].copy_from_slice(b"TZif");
        bytes[36..40].copy_from_slice(&1u32.to_be_bytes());
        bytes[40..44].copy_from_slice(&4u32.to_be_bytes());
        bytes.extend_from_slice(&offset.to_be_bytes());bytes.extend_from_slice(&[0,0]);
        bytes.extend_from_slice(b"ONE\0");
        std::fs::write(path,bytes).unwrap();
    }
    write_zone(path,3600);unsafe {std::env::set_var("TZ",path)};owned_timezone::tzset();
    assert!(!unsafe {owned_calendar::localtime_r(&instant,&mut tm)}.is_null());
    assert_eq!(tm.utc_offset,3600);
    // Atomic replacement supplies a new file while the original mapped inode
    // remains live; unchanged TZ retains that old mapping by the cache contract.
    let replacement=format!("{path}.new");write_zone(&replacement,7200);
    std::fs::rename(&replacement,path).unwrap();owned_timezone::tzset();
    assert!(!unsafe {owned_calendar::localtime_r(&instant,&mut tm)}.is_null());
    assert_eq!(tm.utc_offset,3600);
    unsafe {std::env::set_var("TZ","UTC0")};owned_timezone::tzset();
    unsafe {std::env::set_var("TZ",path)};owned_timezone::tzset();
    assert!(!unsafe {owned_calendar::localtime_r(&instant,&mut tm)}.is_null());
    assert_eq!(tm.utc_offset,7200,"changed TZ drops the old inode and maps the replacement");
    unsafe {std::env::set_var("TZ","UTC0")};owned_timezone::tzset();
    std::fs::remove_file(path).unwrap();
}
