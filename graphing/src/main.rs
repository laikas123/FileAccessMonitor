
use std::error::Error;
use serde::Serialize;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::io::BufReader;
use std::fs::File;
use std::io::BufRead;
use plotters::prelude::*;
use chrono::{Utc, DateTime};
use std::time::{UNIX_EPOCH, Duration};
use std::collections::BTreeMap;


pub type GeneralError = Box<dyn Error + Send + Sync + 'static>;
pub type GeneralResult<T> = Result<T, GeneralError>;


const COLORS: [RGBColor; 7] =  [BLUE, GREEN, RED, YELLOW, CYAN, BLACK, WHITE];



#[derive(Debug, Deserialize, Serialize, Clone)]
struct ReadSyscallData {
    timestamp: u128,
    pid: usize,
    uid: i32,
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

fn uid_to_label(uid: i32) -> String {

    match uid {
        490 => "uid:490 accounting".to_string(),
        590 => "uid:590 developers".to_string(),
        690 => "uid:690 marketing".to_string(),
        _ => "unknown user".to_string(),
    }

}



fn main() {
    
    //get data from log file into organize structure
    let map_uid_to_map_hour_to_count = json_file_to_data_by_user::<ReadSyscallData>("/home/logan/read_access.log".to_string()).unwrap();

    //plot the data
    plot_data(map_uid_to_map_hour_to_count);

  
}


fn plot_data(label_data_vec: BTreeMap<i32, BTreeMap<i32, i32>>) {

    let root_area = BitMapBackend::new("/home/logan/2.5.png", (600, 400))
    .into_drawing_area();
    root_area.fill(&WHITE).unwrap();

    let mut ctx = ChartBuilder::on(&root_area)
    .set_label_area_size(LabelAreaPosition::Left, 40)
    .set_label_area_size(LabelAreaPosition::Bottom, 40)
    .caption("Access to Files", ("sans-serif", 40))
    .build_cartesian_2d(0..18, 0..55)
    .unwrap();

    ctx.configure_mesh()
    .x_desc("Hour of Day")
    .y_desc("Number of Accesses")
    .axis_desc_style(("sans-serif", 15)).draw().unwrap();


   
    
    let mut color_index = 0;

    for (uid, map_hour_count) in label_data_vec{
        match color_index {
            0 => {
                ctx.draw_series(LineSeries::new(map_hour_count.iter().map(|x| (*x.0, *x.1)), &COLORS[0])
            ).unwrap().label(uid_to_label(uid)).legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &COLORS[0]));
            },
            1 => {
                ctx.draw_series(LineSeries::new(map_hour_count.iter().map(|x| (*x.0, *x.1)), &COLORS[1])
            ).unwrap().label(uid_to_label(uid)).legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &COLORS[1]));
            },
            2 => {
                ctx.draw_series(LineSeries::new(map_hour_count.iter().map(|x| (*x.0, *x.1)), &COLORS[2])
            ).unwrap().label(uid_to_label(uid)).legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &COLORS[2]));
            },
            3 => {
                ctx.draw_series(LineSeries::new(map_hour_count.iter().map(|x| (*x.0, *x.1)), &COLORS[3])
            ).unwrap().label(uid_to_label(uid)).legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &COLORS[3]));
            },
            4 => {
                ctx.draw_series(LineSeries::new(map_hour_count.iter().map(|x| (*x.0, *x.1)), &COLORS[4])
            ).unwrap().label(uid_to_label(uid)).legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &COLORS[4]));
            },
            5 => {
                ctx.draw_series(LineSeries::new(map_hour_count.iter().map(|x| (*x.0, *x.1)), &COLORS[5])
            ).unwrap().label(uid_to_label(uid)).legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &COLORS[5]));
            },
            _ => {
                ctx.draw_series(LineSeries::new(map_hour_count.iter().map(|x| (*x.0, *x.1)), &COLORS[6])
            ).unwrap().label(uid_to_label(uid)).legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &COLORS[6]));
            },
        }
      
        color_index += 1;
    }

   
    ctx.configure_series_labels()
        .border_style(&BLACK)
        .background_style(&WHITE.mix(0.8))
        .draw()
        .unwrap();

    

}


//get timestamp in nano seconds to date struct
//for human readable format
fn filter_time(timestamp: u128)  -> DateStruct{
    // Creates a new SystemTime from the specified number of whole seconds
    let d = UNIX_EPOCH + Duration::from_nanos(timestamp.try_into().unwrap());
    // Create DateTime from SystemTime
    let datetime = DateTime::<Utc>::from(d);
    // Formats the combined date and time with the specified format string.
    let datestruct_str = datetime.format("%Y-%m-%d-%H-%M-%S-%f").to_string();
    let parts: Vec<String> = datestruct_str.split("-").map(|elem| elem.trim_start_matches('0').to_string()).collect();
    
    //convert to date struct for easy access 
    //of date parts
    let datestruct = DateStruct::new(parts);

    datestruct

}


//on success return BTreeMap<i32, BTreeMap<i32, i32>> 
//the first key is the uid, 
fn json_file_to_data_by_user<P>(filename: String) -> GeneralResult<BTreeMap<i32, BTreeMap<i32, i32>>> where P: DeserializeOwned +  std::fmt::Debug,{
   
   
    let mut map_uid_to_map_hour_to_count: BTreeMap<i32, BTreeMap<i32, i32>> = BTreeMap::new();

    let file = File::open(filename).unwrap(); 
    // Read the file line by line, and return an iterator of the lines of the file.
    let lines = BufReader::new(file).lines(); 

    for line in lines{
        let parsed: ReadSyscallData = serde_json::from_str(&line.unwrap())?;

        let uid = parsed.uid;
        let hour = filter_time(parsed.timestamp).hour;

        

        if let Some(map_hour_to_count) = map_uid_to_map_hour_to_count.get_mut(&uid){
        
            if let Some(count) = (*map_hour_to_count).get_mut(&hour) {
                *count += 1;
            }else{
                (*map_hour_to_count).insert(hour, 1);
            }

        }else{
            let mut new_hour_to_count = BTreeMap::new();
            new_hour_to_count.insert(hour, 1);
            map_uid_to_map_hour_to_count.insert(uid, new_hour_to_count);
        }

        
    }

    for i in 0..24 {
        for (_, map_hour_count) in &mut map_uid_to_map_hour_to_count {
            
            if !map_hour_count.contains_key(&i){
                map_hour_count.insert(i, 0);
            }
        }
    }

  
    Ok(map_uid_to_map_hour_to_count)

    
}

