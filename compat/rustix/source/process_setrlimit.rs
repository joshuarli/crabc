use api::process;

fn check_source_shape() {
    let limit = process::Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    let _ = process::setrlimit(process::Resource::Core, limit);
}

fn main() {
    let _ = check_source_shape as fn();
    println!("native-process-setrlimit ok");
}
