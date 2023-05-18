
use std::error::Error;
use serde::Serialize;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::io::BufReader;
use std::fs::File;
use std::io::BufRead;
use plotters::prelude::*;
use chrono::{Utc, TimeZone, DateTime};
use std::time::{SystemTime, UNIX_EPOCH, Duration};

use std::collections::HashSet;
use std::collections::BTreeSet;


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

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}

fn num_to_color(num: &usize) -> &'static RGBColor {
    &COLORS[*num]
}

fn main() {
    

    // let data_vec: Vec<(i32, i32)>  = json_file_to_data::<ReadSyscallData>("/home/logan/read_access.log".to_string()).unwrap();


    // let min_timestamp: i32 = data_vec[0].0;
    // let max_timestamp: i32 = (*data_vec.iter().last().unwrap()).0;

    // println!("min {:?}, max {:?}", min_timestamp, max_timestamp);


    
   
    let mut map_uid_to_map_hour_to_count = json_file_to_data_by_user::<ReadSyscallData>("/home/logan/read_access.log".to_string()).unwrap();

    print_type_of(&GREEN);
    
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
    .y_desc("")
    .axis_desc_style(("sans-serif", 15)).draw().unwrap();


    for i in 0..label_data_vec.len() {

    }

    
    let mut color_index = 0;

    for (uid, map_hour_count) in label_data_vec{
        match color_index {
            0 => {
                ctx.draw_series(LineSeries::new(map_hour_count.iter().map(|x| (*x.0, *x.1)).inspect(|elem| println!("elem {:?}", elem)), &COLORS[0])
            ).unwrap().label(uid.to_string()).legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &COLORS[0]));
            },
            1 => {
                ctx.draw_series(LineSeries::new(map_hour_count.iter().map(|x| (*x.0, *x.1)).inspect(|elem| println!("elem {:?}", elem)), &COLORS[1])
            ).unwrap().label(uid.to_string()).legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &COLORS[1]));
            },
            2 => {
                ctx.draw_series(LineSeries::new(map_hour_count.iter().map(|x| (*x.0, *x.1)).inspect(|elem| println!("elem {:?}", elem)), &COLORS[2])
            ).unwrap().label(uid.to_string()).legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &COLORS[2]));
            },
            3 => {
                ctx.draw_series(LineSeries::new(map_hour_count.iter().map(|x| (*x.0, *x.1)).inspect(|elem| println!("elem {:?}", elem)), &COLORS[3])
            ).unwrap().label(uid.to_string()).legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &COLORS[3]));
            },
            4 => {
                ctx.draw_series(LineSeries::new(map_hour_count.iter().map(|x| (*x.0, *x.1)).inspect(|elem| println!("elem {:?}", elem)), &COLORS[4])
            ).unwrap().label(uid.to_string()).legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &COLORS[4]));
            },
            5 => {
                ctx.draw_series(LineSeries::new(map_hour_count.iter().map(|x| (*x.0, *x.1)).inspect(|elem| println!("elem {:?}", elem)), &COLORS[5])
            ).unwrap().label(uid.to_string()).legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &COLORS[5]));
            },
            _ => {
                ctx.draw_series(LineSeries::new(map_hour_count.iter().map(|x| (*x.0, *x.1)).inspect(|elem| println!("elem {:?}", elem)), &COLORS[6])
            ).unwrap().label(uid.to_string()).legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &COLORS[6]));
            },
        }
        // ctx.draw_series(LineSeries::new(map_hour_count.iter().map(|x| (*x.0, *x.1)).inspect(|elem| println!("elem {:?}", elem)), color)
        //     ).unwrap().label(uid.to_string()).legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], color));

        color_index += 1;
    }

    // println!("color index is {}", color_index);

    //   ctx.draw_series(
    //     LineSeries::new(data_vec.iter().map(|x| (x.0, x.1)).inspect(|elem| println!("elem {:?}", elem)), &GREEN)
    //   ).unwrap().label("Line").legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &GREEN));

    //   ctx.draw_series(
    //         data_vec.iter().map(|point| TriangleMarker::new(*point, 5, &BLUE)),
    //     ).unwrap().label("Scatter").legend(|(x, y)| PathElement::new(vec![(x, y), (x + 5, y)], &BLUE));

    ctx.configure_series_labels()
        .border_style(&BLACK)
        .background_style(&WHITE.mix(0.8))
        .draw()
        .unwrap();

    

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


//returns a BTreeMap such that:
//
//Key = uid
//
//Value = vec of tuples where first element is the hour, 
//second element is the number of reads to file
fn json_file_to_data_by_user<P>(filename: String) -> GeneralResult<BTreeMap<i32, BTreeMap<i32, i32>>> where P: DeserializeOwned +  std::fmt::Debug,{
   
   
    let mut map_uid_to_map_hour_to_count: BTreeMap<i32, BTreeMap<i32, i32>> = BTreeMap::new();

    let file = File::open(filename).unwrap(); 
    // Read the file line by line, and return an iterator of the lines of the file.
    let lines = BufReader::new(file).lines(); 

    for line in lines{
        let parsed: ReadSyscallData = serde_json::from_str(&line.unwrap())?;

        let uid = parsed.uid;
        let hour = filter_time(parsed.timestamp).hour;

        println!("uid = {} hour = {} map_hour_to_count {:?}", uid, hour, map_uid_to_map_hour_to_count);

        if let Some(map_hour_to_count) = map_uid_to_map_hour_to_count.get_mut(&uid){
            // println!("{:?}", *map_hour_to_count);
            // *map_hour_to_count.get_mut(&hour).unwrap() += 1;
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
        for (uid, map_hour_count) in &mut map_uid_to_map_hour_to_count {
            // println!("{}, {:?}", uid, map_hour_count);
            if !map_hour_count.contains_key(&i){
                map_hour_count.insert(i, 0);
            }
        }
    }

    
    // println!("{:?}", data_by_uid_vec);

    for map in &map_uid_to_map_hour_to_count{
        println!("{:?}", map);
    }



   

    //need a datapoint for every hour of the day
    // for i in 0..24 {
    //     if let Some(count) = btreemap.get(&i) {
    //         dat_vec.push((i, *count));
    //     }else{
    //         dat_vec.push((i, 0));
    //     }
    // }

    

    Ok(map_uid_to_map_hour_to_count)

    
}

