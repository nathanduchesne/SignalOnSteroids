use rrc::*;
use rc::*;

#[allow(dead_code)]
pub struct RrcSendCtWrapper {
    pub flag: usize, 
    ordinal: Ordinal,
    ct: Ciphertext,
    header: Header
}

/// Initialize the states of both parties
pub fn rc_arc_init() -> (RrcState, RrcState) {
    return rrc_init_all(Security::RRid);
}

/// Send an encrypted message to the other party with UNF-Security
pub fn rc_arc_send(state: &mut RrcState, associated_data: &[u8; 32], pt: &[u8]) -> RrcSendCtWrapper {
    let (ord, ct, header) = rrc_send(state, associated_data, pt);
    return RrcSendCtWrapper{flag: 0, ordinal: ord, ct: ct, header: header};
}

/// Receive an encrypted message from the other party with UNF-Security
pub fn rc_arc_receive(state: &mut RrcState, associated_data: &[u8; 32], ct: &mut RrcSendCtWrapper) -> (bool, Ordinal, Vec<u8>) {
    if ct.flag != 0 {
        return (false, Ordinal{epoch: 0, index: 0}, Vec::new());
    }
    return rrc_receive(state, associated_data, &mut ct.ct, ct.header);
}

/// Send an authentication tag to the other party for out-of-bands verification
pub fn rc_arc_auth_send(state: &mut RrcState) -> RrcSendCtWrapper {
    let fake_ad: [u8; 32] = [0; 32];
    let fake_ct = b"0";
    let (ord, ct, header) = rrc_send(state, &fake_ad, fake_ct);
    return RrcSendCtWrapper{flag: 1, ordinal: ord, ct: ct, header: header};
}

/// Receive an authentication tag from the other party for out-of-bands verification
pub fn rc_arc_auth_receive(state: &mut RrcState, at: &mut RrcSendCtWrapper) -> (bool, Ordinal){
    if at.flag != 1 {
        return (false, Ordinal{epoch: 0, index: 0});
    }
    let fake_ad: [u8; 32] = [0; 32];
    let (acc, ord, _) = rrc_receive(state, &fake_ad, &mut at.ct, at.header);
    return (acc, ord);
}