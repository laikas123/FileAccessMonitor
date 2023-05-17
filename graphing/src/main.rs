
use std::error::Error;
use serde::Serialize;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::io::BufReader;
use std::fs::File;
use std::io::BufRead;
use plotters::prelude::*;
use chrono::{Utc, TimeZone, DateTime};
const DATA: [f64; 14] = [ 137.24, 136.37, 138.43, 137.41, 139.69, 140.41, 141.58, 139.55, 139.68, 139.10, 138.24, 135.67, 137.12, 138.12];
use std::time::{SystemTime, UNIX_EPOCH, Duration};




use std::collections::BTreeMap;


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

#[derive(Debug, Deserialize, Serialize)]
struct DateStruct {
    year: u16,
    month: u8,
    day: u8,
    hour: i32,
    min: u8,
    sec: u8,
    nano: u64,
}

impl DateStruct {

    fn new(parts: Vec<String>) -> Self {
        DateStruct{
            year: parts[0].parse().unwrap(),
            month: parts[1].parse().unwrap(),
            day: parts[2].parse().unwrap(),
            hour: parts[3].parse().unwrap(),
            min: parts[4].parse().unwrap(),
            sec: parts[5].parse().unwrap(),
            nano: parts[6].parse().unwrap(),
        }
    }

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

    let (timestamps, pids, uids, fds, inodes, commands) = json_file_to_data("/home/logan/read_access.log".to_string()).unwrap();

    

    let bmap: Vec<(i32, i32)>  = json_file_to_data::<ReadSyscallData>("/home/logan/read_access.log".to_string()).unwrap();


    println!("{:?}", bmap);

    let min_timestamp: i32 = bmap[0].0;
    let max_timestamp: i32 = (*bmap.iter().last().unwrap()).0;

    println!("min {:?}, max {:?}", min_timestamp, max_timestamp);


    

    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    println!("{:?}", since_the_epoch);

   
    

    let in_mc = since_the_epoch.as_micros();
    let in_ms = since_the_epoch.as_nanos();

    println!("{}, in_ms", in_ms);
    println!("{}, in_ms", in_mc);


    let mydatastruct = DateStruct{
        year: 2023,
        month: 05,
        day: 17,
        hour: 1,
        min: 49,
        sec: 14,
        nano: 246414904,
    };

    data_to_json_file(&mydatastruct);





    let root_area = BitMapBackend::new("/home/logan/2.5.png", (600, 400))
    .into_drawing_area();
  root_area.fill(&WHITE).unwrap();

  let mut ctx = ChartBuilder::on(&root_area)
    .set_label_area_size(LabelAreaPosition::Left, 40)
    .set_label_area_size(LabelAreaPosition::Bottom, 40)
    .caption("Line Plot Demo", ("sans-serif", 40))
    .build_cartesian_2d(0..18, 0..20)
    .unwrap();

  ctx.configure_mesh()
  .x_desc("Seconds")
  .y_desc("% Busy")
  .axis_desc_style(("sans-serif", 15)).draw().unwrap();

  ctx.draw_series(
    LineSeries::new(bmap.iter().map(|x| (x.0, x.1)).inspect(|elem| println!("elem {:?}", elem)), &GREEN)
  ).unwrap().label("Line").legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &GREEN));

  ctx.draw_series(
        bmap.iter().map(|point| TriangleMarker::new(*point, 5, &BLUE)),
    ).unwrap().label("Scatter").legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &BLUE));

    ctx.configure_series_labels()
        .border_style(&BLACK)
        .background_style(&WHITE.mix(0.8))
        .draw()
        .unwrap();

}


fn plot_data(data: Vec<(String, Vec<(i32, i32)>)) {

    

}




fn json_file_to_data(filename: String) -> GeneralResult<(Vec<u128>, Vec<usize>, Vec<usize>, Vec<i16>, Vec<usize>, Vec<String>)> {
   

    let file = File::open(filename).unwrap(); 
    // Read the file line by line, and return an iterator of the lines of the file.
    let lines = BufReader::new(file).lines(); 

    let mut timestamps = Vec::new();
    let mut pids = Vec::new();
    let mut uids = Vec::new();
    let mut fds = Vec::new();
    let mut inodes = Vec::new();
    let mut commands = Vec::new();
    

    for line in lines{
        let parsed: ReadSyscallData = serde_json::from_str(&line.unwrap())?;

        timestamps.push(parsed.timestamp);
        pids.push(parsed.pid);
        uids.push(parsed.uid);
        fds.push(parsed.fd);
        inodes.push(parsed.inode);
        commands.push(parsed.command.clone());

    }



    Ok((timestamps, pids, uids, fds, inodes, commands))

    
}

fn filter_time(timestamp: u128)  -> DateStruct{
    // Creates a new SystemTime from the specified number of whole seconds
    let d = UNIX_EPOCH + Duration::from_nanos(timestamp.try_into().unwrap());
    // Create DateTime from SystemTime
    let datetime = DateTime::<Utc>::from(d);
    // Formats the combined date and time with the specified format string.
    let timestamp_str = datetime.format("%Y-%m-%d %H:%M:%S.%f").to_string();
    let datestruct_str = datetime.format("%Y-%m-%d-%H-%M-%S-%f").to_string();
    let parts: Vec<String> = datestruct_str.split("-").map(|elem| elem.trim_start_matches('0').to_string()).collect();
    
    //convert to date struct for easy access 
    //of date parts
    let datestruct = DateStruct::new(parts);

    datestruct

    
}


fn json_file_to_data<P>(filename: String) -> GeneralResult<Vec<(i32, i32)>> where P: DeserializeOwned +  std::fmt::Debug,{
   
    let mut result = BTreeMap::new();
    let mut result2 = Vec::new();

    let file = File::open(filename).unwrap(); 
    // Read the file line by line, and return an iterator of the lines of the file.
    let lines = BufReader::new(file).lines(); 

    for line in lines{
        let parsed: ReadSyscallData = serde_json::from_str(&line.unwrap())?;

        let datestruct = filter_time(parsed.timestamp);


        if let Some(hour) = result.get_mut(&datestruct.hour) {
            *hour += 1;
        }else{
            result.insert(datestruct.hour, 1);
        }


        


        // println!("{:?}", parsed);
        // results.push(parsed);
    }

    for (key, val) in result {
        result2.push((key, val));
    }

    println!("result is {:?}", result2);

    Ok(result2)

    
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