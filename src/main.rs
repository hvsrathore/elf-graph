use std::fs;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind};
use object::{Object, ObjectSection};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read("/tmp/test_lazy")?;
    let file = object::File::parse(&*data)?;

    let text_section = file.section_by_name(".text").expect(".text not found");
    let text_data = text_section.data()?;
    let text_addr = text_section.address();

    let mut decoder = Decoder::with_ip(64, text_data, text_addr, DecoderOptions::NONE);
    let mut instr = Instruction::default();

    while decoder.can_decode() {
        let ip = decoder.ip();
        decoder.decode_out(&mut instr);
        if instr.mnemonic() == Mnemonic::Call {
            println!("CALL at 0x{:x}: op0_kind={:?}, flow_control={:?}", ip, instr.op0_kind(), instr.flow_control());
            if matches!(instr.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                println!("  Direct CALL target: 0x{:x}", instr.near_branch_target());
            }
        }
    }

    Ok(())
}
