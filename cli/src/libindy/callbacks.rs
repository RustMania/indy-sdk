use super::ErrorCode;

use utils::sequence::SequenceUtils;

use libc::c_char;

use std::slice;
use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::Mutex;
use std::sync::mpsc::{channel, Receiver};
use rust_base58::ToBase58;

pub fn _closure_to_cb_ec() -> (Receiver<ErrorCode>, i32,
                               Option<extern fn(command_handle: i32,
                                                err: ErrorCode)>) {
    let (sender, receiver) = channel();

    lazy_static! {
        static ref CALLBACKS: Mutex<HashMap<i32, Box<FnMut(ErrorCode) + Send>>> = Default::default();
    }

    let closure = Box::new(move |err| {
        sender.send(err).unwrap();
    });

    extern "C" fn _callback(command_handle: i32, err: ErrorCode) {
        let mut callbacks = CALLBACKS.lock().unwrap();
        let mut cb = callbacks.remove(&command_handle).unwrap();
        cb(err)
    }

    let mut callbacks = CALLBACKS.lock().unwrap();
    let command_handle = SequenceUtils::get_next_id();
    callbacks.insert(command_handle, closure);

    (receiver, command_handle, Some(_callback))
}

pub fn _closure_to_cb_ec_i32() -> (Receiver<(ErrorCode, i32)>, i32,
                                   Option<extern fn(command_handle: i32, err: ErrorCode,
                                                    c_i32: i32)>) {
    let (sender, receiver) = channel();

    lazy_static! {
        static ref CALLBACKS: Mutex<HashMap<i32, Box<FnMut(ErrorCode, i32) + Send>>> = Default::default();
    }

    let closure = Box::new(move |err, val| {
        sender.send((err, val)).unwrap();
    });

    extern "C" fn _callback(command_handle: i32, err: ErrorCode, c_i32: i32) {
        let mut callbacks = CALLBACKS.lock().unwrap();
        let mut cb = callbacks.remove(&command_handle).unwrap();
        cb(err, c_i32)
    }

    let mut callbacks = CALLBACKS.lock().unwrap();
    let command_handle = SequenceUtils::get_next_id();
    callbacks.insert(command_handle, closure);

    (receiver, command_handle, Some(_callback))
}

pub fn _closure_to_cb_ec_string() -> (Receiver<(ErrorCode, String)>, i32,
                                      Option<extern fn(command_handle: i32,
                                                       err: ErrorCode,
                                                       c_str: *const c_char)>) {
    let (sender, receiver) = channel();

    lazy_static! {
        static ref CALLBACKS: Mutex < HashMap < i32, Box < FnMut(ErrorCode, String) + Send > >> = Default::default();
    }

    let closure = Box::new(move |err, val| {
        sender.send((err, val)).unwrap();
    });

    extern "C" fn _callback(command_handle: i32, err: ErrorCode, c_str: *const c_char) {
        let mut callbacks = CALLBACKS.lock().unwrap();
        let mut cb = callbacks.remove(&command_handle).unwrap();
        let metadata = unsafe { CStr::from_ptr(c_str).to_str().unwrap().to_string() };
        cb(err, metadata)
    }

    let mut callbacks = CALLBACKS.lock().unwrap();
    let command_handle = SequenceUtils::get_next_id();
    callbacks.insert(command_handle, closure);

    (receiver, command_handle, Some(_callback))
}

pub fn _closure_to_cb_ec_string_string() -> (Receiver<(ErrorCode, String, String)>, i32,
                                             Option<extern fn(command_handle: i32,
                                                              err: ErrorCode,
                                                              str1: *const c_char,
                                                              str2: *const c_char)>) {
    let (sender, receiver) = channel();

    lazy_static! {
            static ref CALLBACKS: Mutex < HashMap < i32, Box < FnMut(ErrorCode, String, String) + Send > >> = Default::default();
    }

    let closure = Box::new(move |err, val1, val2| {
        sender.send((err, val1, val2)).unwrap();
    });

    extern "C" fn _callback(command_handle: i32, err: ErrorCode, str1: *const c_char, str2: *const c_char) {
        let mut callbacks = CALLBACKS.lock().unwrap();
        let mut cb = callbacks.remove(&command_handle).unwrap();
        let str1 = unsafe { CStr::from_ptr(str1).to_str().unwrap().to_string() };
        let str2 = unsafe { CStr::from_ptr(str2).to_str().unwrap().to_string() };
        cb(err, str1, str2)
    }

    let mut callbacks = CALLBACKS.lock().unwrap();
    let command_handle = SequenceUtils::get_next_id();
    callbacks.insert(command_handle, closure);

    (receiver, command_handle, Some(_callback))
}


pub fn _closure_to_cb_ec_string_string_string() -> (Receiver<(ErrorCode, String, String, String)>, i32,
                                             Option<extern fn(command_handle: i32,
                                                              err: ErrorCode,
                                                              str1: *const c_char,
                                                              str2: *const c_char,
                                                              str3: *const c_char)>) {
    let (sender, receiver) = channel();

    lazy_static! {
            static ref CALLBACKS: Mutex < HashMap < i32, Box < FnMut(ErrorCode, String, String, String) + Send > >> = Default::default();
    }

    let closure = Box::new(move |err, val1, val2, val3 | {
        sender.send((err, val1, val2, val3)).unwrap();
    });

    extern "C" fn _callback(command_handle: i32, err: ErrorCode, str1: *const c_char, str2: *const c_char, str3: *const c_char) {
        let mut callbacks = CALLBACKS.lock().unwrap();
        let mut cb = callbacks.remove(&command_handle).unwrap();
        let str1 = unsafe { CStr::from_ptr(str1).to_str().unwrap().to_string() };
        let str2 = unsafe {   if !str2.is_null() {CStr::from_ptr(str2).to_str().unwrap().to_string()} else {String::new()} };
        let str3 = unsafe {   if !str3.is_null() {CStr::from_ptr(str3).to_str().unwrap().to_string()} else {String::new()} };
        cb(err, str1, str2, str3)
    }

    let mut callbacks = CALLBACKS.lock().unwrap();
    let command_handle = SequenceUtils::get_next_id();
    callbacks.insert(command_handle, closure);

    (receiver, command_handle, Some(_callback))
}



pub fn _closure_to_cb_ec_message58() -> (Receiver<(ErrorCode, String)>, i32,
                                             Option<extern fn(command_handle: i32,
                                                              err: ErrorCode,
                                                              encrypted_msg: *const u8,
                                                              encrypted_len: u32)>) {

    let (sender, receiver) = channel();

    lazy_static! {
        static ref CALLBACKS: Mutex < HashMap < i32, Box < FnMut(ErrorCode, String) + Send > >> = Default::default();
    }


    let closure = Box::new(move |err, val1| {
        sender.send((err, val1)).unwrap();
    });

    extern "C" fn _callback(command_handle: i32, err: ErrorCode, msg: *const u8, len: u32) {
        let mut callbacks = CALLBACKS.lock().unwrap();
        let mut cb = callbacks.remove(&command_handle).unwrap();
        let str = unsafe {
            let _slice = slice::from_raw_parts(msg,len as usize);
            _slice.to_base58()
        };
        cb(err, str)
    }

    let mut callbacks = CALLBACKS.lock().unwrap();
    let command_handle = SequenceUtils::get_next_id();
    callbacks.insert(command_handle, closure);

    (receiver, command_handle, Some(_callback))
}


pub fn _closure_to_cb_ec_message() -> (Receiver<(ErrorCode, String)>, i32,
                                         Option<extern fn(command_handle: i32,
                                                          err: ErrorCode,
                                                          msg: *const u8,
                                                          len: u32)>) {
    let (sender, receiver) = channel();

    lazy_static! {
        static ref CALLBACKS: Mutex < HashMap < i32, Box < FnMut(ErrorCode, String) + Send > >> = Default::default();
    }


    let closure = Box::new(move |err, val1| {
        sender.send((err, val1)).unwrap();
    });

    extern "C" fn _callback(command_handle: i32, err: ErrorCode, msg: *const u8, len: u32) {
        let mut callbacks = CALLBACKS.lock().unwrap();
        let mut cb = callbacks.remove(&command_handle).unwrap();
        let str = unsafe {
            let _slice = slice::from_raw_parts(msg, len as usize);
            let vec = Vec::from(_slice);
            String::from_utf8(vec).unwrap()
        };
        cb(err, str)
    }

    let mut callbacks = CALLBACKS.lock().unwrap();
    let command_handle = SequenceUtils::get_next_id();
    callbacks.insert(command_handle, closure);

    (receiver, command_handle, Some(_callback))
}

pub fn _closure_to_cb_ec_message_withkey() -> (Receiver<(ErrorCode, String,String)>, i32,
                                       Option<extern fn(command_handle: i32,
                                                        err: ErrorCode,
                                                        their_vk: *const c_char,
                                                        msg: *const u8,
                                                        len: u32)>) {
    let (sender, receiver) = channel();

    lazy_static! {
        static ref CALLBACKS: Mutex < HashMap < i32, Box < FnMut(ErrorCode, String, String) + Send > >> = Default::default();
    }


    let closure = Box::new(move |err, val1, val2 | {
        sender.send((err, val1, val2)).unwrap();
    });

    extern "C" fn _callback(command_handle: i32, err: ErrorCode,  their_vk: *const c_char,  msg: *const u8, len: u32) {
        let mut callbacks = CALLBACKS.lock().unwrap();
        let mut cb = callbacks.remove(&command_handle).unwrap();
        let msg = unsafe {
            let _slice = slice::from_raw_parts(msg, len as usize);
            let vec = Vec::from(_slice);
            String::from_utf8(vec).unwrap()
        };
        let their_key = unsafe { CStr::from_ptr(their_vk).to_str().unwrap().to_string() };
        cb(err, msg, their_key)
    }

    let mut callbacks = CALLBACKS.lock().unwrap();
    let command_handle = SequenceUtils::get_next_id();
    callbacks.insert(command_handle, closure);

    (receiver, command_handle, Some(_callback))
}