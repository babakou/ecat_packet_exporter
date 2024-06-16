use clap::Parser;
use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::fmt::Display;
use std::fs::File;
use std::process::exit;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    file: String,
}

#[derive(Default)]
struct EtherNetFrame<'a> {
    frame_type: u16, //should be 0x88a4(EtherCAT Frame) in this application.
    ecat_frame: EtherCATFrame<'a>
}

impl<'a> EtherNetFrame<'a> {
    fn parse(data: &'a [u8]) -> Self {
        let mut dst_mac: [u8; 6] = [0; 6];
        dst_mac.copy_from_slice(&data[0..6]);

        let mut src_mac: [u8; 6] = [0; 6];
        src_mac.copy_from_slice(&data[6..12]);

        let frame_type = u16::from_be_bytes([data[12], data[13]]);

        EtherNetFrame {
            frame_type,
            ecat_frame: EtherCATFrame::parse(dst_mac, src_mac, &data[14..])
        }
    }
}

#[derive(Default)]
struct EtherCATFrame<'a> {
    header: EtherCATFrameHeader,
    datagrams: Vec<EtherCATDatagram<'a>>,
}

impl<'a> EtherCATFrame<'a> {
    fn parse(dst_mac: [u8; 6], src_mac: [u8; 6], data: &'a [u8]) -> Self {
        let len_rsv_type = u16::from_le_bytes([data[0], data[1]]);
        let length = len_rsv_type & 0x07_FF;
        let reserved: u8 = (len_rsv_type >> 11) as u8 & 0x1;
        let ecat_frame_type = (len_rsv_type >> 12) as u8 & 0xF;
        EtherCATFrame {
            header: EtherCATFrameHeader {
                length,
                reserved,
                ecat_frame_type
            },
            datagrams: EtherCATDatagram::parse_datagrams(dst_mac, src_mac, &data[2..])
        }
    }
}

#[derive(Default)]
struct EtherCATFrameHeader {
    length: u16,
    reserved: u8,
    ecat_frame_type: u8,
}

#[derive(Default, Debug)]
struct EtherCATDatagram<'a> {
    header: EtherCATDatagramHeader,
    data: &'a [u8],
    wkc: u16,
}

impl<'a> EtherCATDatagram<'a> {
    fn parse_datagrams(dst_mac: [u8; 6], src_mac: [u8; 6], data_buf: &'a[u8]) -> Vec<Self> {
        let mut datagrams = Vec::new();
        let mut next_datagram_offset = 0;
        loop {
            let datagram = EtherCATDatagram::parse_one_datagram(&data_buf[next_datagram_offset..]);
            let is_last_datagram = datagram.is_last_datagram();
            next_datagram_offset += datagram.size();

            //datagrams.push(datagram);
            let dst_mac_str = format!("{:x} {:x} {:x} {:x} {:x} {:x}", dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
            let src_mac_str = format!("{:x} {:x} {:x} {:x} {:x} {:x}", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
            println!("{},{},{}",dst_mac_str, src_mac_str, datagram);

            if is_last_datagram {
                break;
            }
        }
        datagrams
    }
    fn parse_one_datagram(data_buf: &'a[u8]) -> Self {
        let cmd: EtherCATCommand = match data_buf[0] {
            0 => EtherCATCommand::NOP,
            1 => EtherCATCommand::APRD,
            2 => EtherCATCommand::APWR,
            3 => EtherCATCommand::APRW,
            4 => EtherCATCommand::FPRD,
            5 => EtherCATCommand::FPWR,
            6 => EtherCATCommand::FPRW,
            7 => EtherCATCommand::BRD,
            8 => EtherCATCommand::BWR,
            9 => EtherCATCommand::BRW,
            10 => EtherCATCommand::LRD,
            11 => EtherCATCommand::LWR,
            12 => EtherCATCommand::LRW,
            13 => EtherCATCommand::ARMW,
            14 => EtherCATCommand::FRMW,
            _ => EtherCATCommand::UNKNOWN,
        };
        let index = data_buf[1];
        let slave_addr = u16::from_le_bytes([data_buf[2], data_buf[3]]);
        let offset_addr = u16::from_le_bytes([data_buf[4], data_buf[5]]);
        let len_rtr_last = u16::from_le_bytes([data_buf[6], data_buf[7]]);
        let length = len_rtr_last & 0x07_FF;
        let round_trip = (len_rtr_last >> 14) as u8 & 0x1;
        let last_indicator = (len_rtr_last >> 15) as u8 & 0x1;
        let irq = u16::from_le_bytes([data_buf[8], data_buf[9]]);
        let data = &data_buf[10..];
        let wkc = u16::from_le_bytes([data_buf[10 + length as usize], data_buf[11 + length as usize]]);

        let datagram = EtherCATDatagram {
            header: EtherCATDatagramHeader {
                cmd,
                index,
                slave_addr,
                offset_addr,
                length,
                round_trip,
                last_indicator,
                irq
            },
            data,
            wkc
        };

        //println!("{:x?}", datagram);

        datagram
    }

    fn is_last_datagram(&self) -> bool {
        self.header.last_indicator == 0
    }

    fn size(&self) -> usize {
        10 + self.header.length as usize + 2 // 10 indicates header, 2 indicates wkc.
    }
}

impl Display for EtherCATDatagram<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{},{},{:x?}", self.header, self.wkc, self.data)
    }
}

#[derive(Default, Debug)]
struct EtherCATDatagramHeader {
    cmd: EtherCATCommand,
    index: u8,
    slave_addr: u16,
    offset_addr: u16,
    length: u16,
    round_trip: u8,
    last_indicator: u8,
    irq: u16,
}

impl Display for EtherCATDatagramHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{},{},{},{:x},{},{},{},{:x}", self.cmd, self.index, self.slave_addr, self.offset_addr, self.length, self.round_trip, self.last_indicator, self.irq)
    }
}

#[derive(Default, Debug)]
enum EtherCATCommand {
    NOP = 0,
    APRD,
    APWR,
    APRW,
    FPRD,
    FPWR,
    FPRW,
    BRD,
    BWR,
    BRW,
    LRD,
    LWR,
    LRW,
    ARMW,
    FRMW,
    #[default] UNKNOWN,
}

impl Display for EtherCATCommand{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cmd_str = match self {
            Self::NOP => "NOP",
            Self::APRD => "APRD",
            Self::APWR => "APWR",
            Self::APRW => "APRW",
            Self::FPRD => "FPRD",
            Self::FPWR => "FPWR",
            Self::FPRW => "FPRW",
            Self::BRD => "BRD",
            Self::BWR => "BWR",
            Self::BRW => "BRW",
            Self::LRD => "LRD",
            Self::LWR => "LWR",
            Self::LRW => "LRW",
            Self::ARMW => "ARMW",
            Self::FRMW => "FRMW",
            Self::UNKNOWN => "UNKNOWN"
        };

        write!(f, "{}", cmd_str)
    }
}

fn main(){
    let args = Args::parse();

    let file = match File::open(&args.file) {
        Ok(file) => file,
        Err(e) => {
            println!("Cannot open file {} : {}", args.file, e);
            exit(1);
        }
    };

    let mut num_blocks = 0;
    let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
    let mut if_linktypes = Vec::new();

    fn get_ethernet_packetdata(raw_data: &[u8], linktype: Linktype, len: u32) -> Option<&[u8]> {
        match pcap_parser::data::get_packetdata(raw_data, linktype, len as usize) {
            Some(packet_data) => match packet_data {
                data::PacketData::L2(packet_data) => Some(packet_data),
                _ => None,
            },
            None => None,
        }
    }

    println!("dst_mac,src_mac,cmd,index,adp,ado,length,round_trip,last_ind,irq,wkc,data");

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::NG(Block::SectionHeader(_shb)) => {
                        //println!("got SHB");
                        if_linktypes = Vec::new();
                    },
                    PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                        //println!("got IDB");
                        if_linktypes.push(idb.linktype);
                    },
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        //println!("got EPB");
                        assert!((epb.if_id as usize) < if_linktypes.len());
                        let linktype = if_linktypes[epb.if_id as usize];
                        match get_ethernet_packetdata(epb.data, linktype, epb.caplen) {
                            Some(packet_data) => {
                                let ethernet_frame = EtherNetFrame::parse(packet_data);
                                // println!("dst_mac = {:x?}", ethernet_frame.dst_mac);
                                // println!("src_mac = {:x?}", ethernet_frame.src_mac);
                                // println!("frame_type = {:x?}", ethernet_frame.frame_type);
                                // println!("len = {}", ethernet_frame.ecat_frame.header.length);
                            },
                            None => println!("unknown block"),
                        }
                    },
                    _ => {
                        println!("unknown block");
                    },
                }
                num_blocks += 1;
                reader.consume(offset);
            },
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().unwrap();
            },
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    println!("num_blocks: {}", num_blocks);
}