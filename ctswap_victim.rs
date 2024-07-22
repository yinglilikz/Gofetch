use libaugury_ffi_sys::{pin_cpu, constant_time_cond_swap_64, c_sleep};
use crypto_victim::*;
// std lib
use std::env::args;
use std::io::{Write, Read};
use std::mem::size_of;
// random value lib
use rand::{Rng, thread_rng};
// mem lib
use mmap_rs::MmapOptions;
// network lib
use std::net::{TcpListener, TcpStream};
// P+P lib
use evict_rs::timer::Timer;
use evict_rs::MyTimer;
use evict_rs::{eviction_set_gen64,
    prime_with_dependencies, probe_with_dependencies, 
    evset_vec_to_evset, evset_vec_set_offset};
use evict_rs::allocator::Allocator;
use evict_rs::eviction_set::EvictionSet;

#[inline(always)]
pub fn visit( a : *const u64 ) {
    let mut aa : u64;
    aa = 7 ;
    for i in 0..100u64
    {
        unsafe{ aa += *a.add(i as usize) } ;
    }
    aa += 1 ;
}
pub fn probe_ss<T: Timer>(
    timer: &T,
    evictor: *const u64,
    mut __trash: u64 
) -> u64 {
    timer.time(|| {
        visit(evictor)
    }) | (__trash & MSB_MASK)
}


fn ctswap_handler(
    mut stream: TcpStream,
    sk: u64,
    timer: &MyTimer,
    std_time: u64
) {
    // println!( "-2" ) ;
    let mut input_data = [0u8; 128];  // src <- input; dst <- input+8*64bit
    let mut msg_data = [0u8; 1]; // !0 - start, 0 - finish
    let input_data_ptr = input_data.as_mut_ptr() as *mut u64;
    // Get Mask from secret key
    let mask: u64 = (!sk).wrapping_add(0x1);

    // Allocate the Source and Destination
    let mut dst_data = MmapOptions::new(MmapOptions::page_size().1)
        .map_mut()
        .unwrap();
    dst_data.fill(0x00);
    let dst_data_ptr: *mut u64 = dst_data.as_mut_ptr() as *mut u64;
    let mut src_data = MmapOptions::new(MmapOptions::page_size().1)
        .map_mut()
        .unwrap();
    src_data.fill(0x00);
    let src_data_ptr: *mut u64 = unsafe{src_data.as_mut_ptr().add(0x1234)} as *mut u64;
    println!("dst_data addr: {:p}", dst_data_ptr);
    println!("src_data addr: {:p}", src_data_ptr);
    println!("input_data addr: {:p}", input_data_ptr);
    // println!( "-1" ) ;

    // main loop
    loop {
        // Receive Client Request (Synchronize each logical transaction)
        // println!( "0" ) ;
        stream.read_exact(&mut msg_data).unwrap();
        // println!( "1" ) ;
        // print!("[+] Start -> ");
        if msg_data[0] == 0 {
            println!("Finish task for {}", stream.peer_addr().unwrap());
            break;
        }
        // println!( "2" ) ;
        // Send Public Key (Attacker won't use Victim pubkey
        // to simplify, just send anything)
        stream.write_all(&msg_data).unwrap();
        // println!( "3" ) ;

        // Receive CC
        stream.read_exact(&mut input_data).unwrap();
        // println!( "4" ) ;

        // prepare data
        for i in 0..8 {
            unsafe{*src_data_ptr.add(i) = *input_data_ptr.add(i);}
            unsafe{*dst_data_ptr.add(i) = *input_data_ptr.add(8+i);}
        }
        // println!( "5" ) ;
        // CT SWAP
        let mut bbb = 0 ;
        for i in 0..8 {
            // println!( "6" ) ;
            unsafe{constant_time_cond_swap_64(mask, src_data_ptr.add(i), dst_data_ptr.add(i));}
            // println!( "7" ) ;
            // add delay
            unsafe{*src_data_ptr = *src_data_ptr | (c_sleep(15000, *src_data_ptr) & MSB_MASK);}
            //ADD
            //Test time to access data
                let mut test_time: u64;
                let mut __trash: u64 = 0;
                test_time = probe_ss(timer, src_data_ptr, __trash);
                println!( "___time: {}" , test_time ) ;
                if test_time > std_time {
                    bbb += 1 ;
                }
            //END
        }
        if( bbb > 5 )
        {
            println!( "under attack!!!" ) ;
        }
        for i in 0..8 {
            unsafe{*src_data_ptr.add(i) = 0;}
            unsafe{*dst_data_ptr.add(i) = 0;}
        }


        // Send FIN
        // clean dst_data and src_data
        msg_data[0] = (unsafe{*src_data_ptr} & MSB_MASK) as u8;
        stream.write_all(&msg_data).unwrap();
        // println!("[+] End");
        // stream.flush().unwrap();
    }
}

fn main() {
    let sk = args().nth(1).expect("Enter <secret key 0 or 1>");
    let sk = sk.parse::<u64>().unwrap();
    println!("[+] Secret Key: {}", sk);
    // pin to performance core
    unsafe{ pin_cpu(7); }

    //ADD
    let timer = MyTimer::new();
    let mut std_time: u64;
    let mut test_time: u64;
    std_time = 0 ;
    let mut aa = [0u64;128] ;
    //Load into Cache
    let mut __trash: u64 = 0;
    test_time = probe_ss(&timer, aa.as_ptr() , __trash);
    test_time += probe_ss(&timer, aa.as_ptr() , __trash);
    test_time += probe_ss(&timer, aa.as_ptr() , __trash);
    for i in 1..32{
        //Test time to access things in chche
        test_time = probe_ss(&timer, aa.as_ptr() , __trash);
        std_time += test_time ;
        println!( "____time: {}", test_time ) ;
        __trash = test_time | (__trash & MSB_MASK);
    }
    std_time = std_time / 32 + 20 ;
    //END
    let listener = TcpListener::bind("0.0.0.0:3333").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Weak CTSWAP Server listening on port 3333");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // println!( "-5" ) ;
                println!("New connection: {}", stream.peer_addr().unwrap());

                // connection succeeded
                // Call Constant Time Swap handler
                ctswap_handler(stream, sk, &timer, std_time);
            },
            Err(e) => {
                println!("Error: {}", e);
                /* connection failed */
            }
        };
    }

    // close the socket server
    drop(listener);
}