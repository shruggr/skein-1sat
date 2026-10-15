//! The ordinal position rule: which output a 1-sat input's satoshi lands in,
//! and which input a 1-sat output's satoshi came from. A port of 1sat-stack
//! pkg/types/ordinal.go `OrdinalOutput` / `OrdinalInput`, null cases and
//! errors included.
//!
//! The source outputs come from `sources`, any value with
//! `sourceOutput(input_index: usize) ?bsvz.transaction.Output` (skein-overlay's
//! `topic.Call` is one); `Hydrated` reads them from the inputs themselves
//! (`source_output` / `source_transaction`, as a BEEF fills them).
const bsvz = @import("bsvz");

const Transaction = bsvz.transaction.Transaction;

pub const Error = error{
    /// `vin` / `vout` is not an index of the transaction.
    OutOfRange,
    /// An input the rule reads has no known source output.
    MissingSourceOutput,
};

/// The source outputs a transaction's inputs carry.
pub const Hydrated = struct {
    tx: *const Transaction,

    pub fn sourceOutput(self: Hydrated, input_index: usize) ?bsvz.transaction.Output {
        if (input_index >= self.tx.inputs.len) return null;
        return bsvz.transaction.sourceOutputForInput(&self.tx.inputs[input_index]);
    }
};

fn sourceSatoshis(sources: anytype, i: usize) Error!u64 {
    const out = sources.sourceOutput(i) orelse return error.MissingSourceOutput;
    return sats(out);
}

/// Output satoshis as the u64 the wire carries (bsvz holds them as i64).
fn sats(out: bsvz.transaction.Output) u64 {
    return @bitCast(out.satoshis);
}

/// The output that receives input `vin`'s satoshi. Null when the input is not
/// a single satoshi, or the satoshi lands in a multi-sat output (absorbed) or
/// past the outputs (fee). The offset is the sum of the source satoshis of the
/// inputs before `vin`; zero-satoshi outputs are skipped.
pub fn output(tx: *const Transaction, vin: u32, sources: anytype) Error!?u32 {
    if (vin >= tx.inputs.len) return error.OutOfRange;

    var offset: u64 = 0;
    for (0..vin) |i| offset +%= try sourceSatoshis(sources, i);
    if (try sourceSatoshis(sources, vin) != 1) return null;

    var cumulative: u64 = 0;
    for (tx.outputs, 0..) |out, vout| {
        if (sats(out) == 0) continue;
        if (cumulative == offset) {
            if (sats(out) != 1) return null;
            return @intCast(vout);
        }
        cumulative +%= sats(out);
        if (cumulative > offset) return null;
    }
    return null;
}

/// The input whose satoshi output `vout` (a single satoshi) holds. Null when
/// the output is not a single satoshi, or the satoshi at its offset comes
/// from a multi-sat input or from no input (a fresh inscription).
pub fn input(tx: *const Transaction, vout: u32, sources: anytype) Error!?u32 {
    if (vout >= tx.outputs.len) return error.OutOfRange;
    if (sats(tx.outputs[vout]) != 1) return null;

    var offset: u64 = 0;
    for (tx.outputs[0..vout]) |out| offset +%= sats(out);

    var cumulative: u64 = 0;
    for (0..tx.inputs.len) |vin| {
        const n = try sourceSatoshis(sources, vin);
        if (cumulative == offset) {
            if (n != 1) return null;
            return @intCast(vin);
        }
        cumulative +%= n;
        if (cumulative > offset) return null;
    }
    return null;
}
