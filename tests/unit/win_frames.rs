use super::*;

#[test]
fn driver_structs_match_the_c_layout() {
    assert_eq!(std::mem::size_of::<DivertAddress>(), 80);
    assert_eq!(std::mem::size_of::<PktHdr>(), 16);
}
