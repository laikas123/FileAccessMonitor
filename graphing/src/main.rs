
use std::error::Error;
use serde::Serialize;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::io::BufReader;
use std::fs::File;
use std::io::BufRead;
use plotters::prelude::*;
use chrono::{Utc, TimeZone};
const DATA: [f64; 14] = [ 137.24, 136.37, 138.43, 137.41, 139.69, 140.41, 141.58, 139.55, 139.68, 139.10, 138.24, 135.67, 137.12, 138.12];
use std::time::{SystemTime, UNIX_EPOCH};


pub type GeneralError = Box<dyn Error + Send + Sync + 'static>;
pub type GeneralResult<T> = Result<T, GeneralError>;



#[derive(Debug, Deserialize, Serialize)]
struct ReadSyscallData {
    timestamp: u128,
    pid: usize,
    uid: usize,
    fd: i16,
    inode: usize,
    command: String,
}

fn is_prime(n: i32) -> bool {
    for i in 2..n {
        if n % i == 0 {
            return false;
        }
    }
    true
}

fn main() {
    let test_dat = ReadSyscallData{
        timestamp: 1684288147432831622,
        pid: 40317,
        uid: 1000,
        fd: 3,
        inode: 1319061,
        command: "cat".to_string(),
    };

    data_to_json_file(&test_dat);

    let data = json_file_to_data::<ReadSyscallData>("/home/logan/read_access.log".to_string()).unwrap();

    let (uid0, uid1000): (Vec<_>, Vec<_>) = data
    .into_iter()
    .partition(|n| n.uid == 0);

    println!("UID 0 {:?}", uid0);
    println!("UID 1000 {:?}", uid1000);

    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    println!("{:?}", since_the_epoch);

   
    

    let in_mc = since_the_epoch.as_micros();
    let in_ms = since_the_epoch.as_nanos();

    println!("{}, in_ms", in_ms);
    println!("{}, in_ms", in_mc);


    let root_area = BitMapBackend::new("/home/logan/2.12.png", (600, 400))
    .into_drawing_area();
    root_area.fill(&WHITE).unwrap();

    let mut ctx = ChartBuilder::on(&root_area)
        .set_label_area_size(LabelAreaPosition::Left, 40)
        .set_label_area_size(LabelAreaPosition::Bottom, 40)
        .caption("Legend", ("sans-serif", 40))
        .build_cartesian_2d(1684288147432831622..1684288736175344163, 0..1)
        .unwrap();

    ctx.configure_mesh().draw().unwrap();

    let x_kps: Vec<_> = (-80..80).map(|x| x as f64 / 20.0).collect();
    ctx.draw_series(LineSeries::new(x_kps.iter().map(|x| (*x, x.sin())), &RED))
        .unwrap()
        .label("Sine")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], &RED));

    ctx.draw_series(LineSeries::new(x_kps.iter().map(|x| (*x, x.cos())), &BLUE))
        .unwrap()
        .label("Cosine")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], &BLUE));

    ctx.configure_series_labels()
        .border_style(&BLACK)
        .background_style(&WHITE.mix(0.8))
        .draw()
        .unwrap();
}

fn json_file_to_data<P>(filename: String) -> GeneralResult<Vec<P>> where P: DeserializeOwned +  std::fmt::Debug,{
   
    let mut results = Vec::new();

    let file = File::open(filename).unwrap(); 
    // Read the file line by line, and return an iterator of the lines of the file.
    let lines = BufReader::new(file).lines(); 

    for line in lines{
        let parsed = serde_json::from_str::<P>(&line.unwrap())?;
        println!("{:?}", parsed);
        results.push(parsed);
    }

    Ok(results)

    
}


fn data_to_json_file<P>(data: &P) -> GeneralResult<()> 
    where P: Serialize
{
    // let mut f = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(DB_DIR.to_owned()+db_name+".db")?;
    let json_string = serde_json::to_string(data)?;
    println!("JSON DATA IS {:?}", json_string);
    // f.write_all(json_string.as_bytes())?;
    // f.flush()?;

    Ok(())
}