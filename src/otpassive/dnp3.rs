//! DNP3 application function codes.

pub(super) fn dnp3_function(f: u8) -> (String, bool) {
    let (n, c) = match f {
        0 => ("Confirm", false),
        1 => ("Read", false),
        2 => ("Write", true),
        3 => ("Select", true),
        4 => ("Operate", true),
        5 => ("Direct Operate", true),
        6 => ("Direct Operate (no ack)", true),
        13 => ("Cold Restart", true),
        14 => ("Warm Restart", true),
        15 => ("Initialize Data", true),
        16 => ("Initialize Application", true),
        17 => ("Start Application", true),
        18 => ("Stop Application", true),
        20 => ("Enable Unsolicited", false),
        21 => ("Disable Unsolicited", true),
        27 => ("Delete File", true),
        _ => return (format!("function {f}"), false),
    };
    (n.to_string(), c)
}
