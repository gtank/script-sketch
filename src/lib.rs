#[cfg(test)]
mod tests {
    use bitcoin::blockdata::script::{Script, Instruction};
    use bitcoin::blockdata::opcodes::{all};
    use bitcoin::hashes::{Hash, hash160};

    use std::borrow::Cow;
    use std::collections::HashMap;

    type Stack<'a> = Vec<Cow<'a, [u8]>>;
    type StackResult<'a> = Result<Cow<'a, [u8]>, VMError>;
    type OpHandler<'a> = fn(&mut Stack<'a>) -> StackResult<'a>;

    enum VMError {
        EmptyStack,
        VerifyFailed,
    }

    struct ScriptVM<'a> {
        words: HashMap<u8, &'a[OpHandler<'a>]>,
        stack: Stack<'a>,
    }

    // An empty return that won't be pushed to the stack.
    const RET_NONE: [u8; 0] = [];

    // A stack value indicating a true result
    // XXX: True is actually any non-zero value
    const RET_TRUE: [u8; 1] = [1];

    // A stack value indicating a false result
    const RET_FALSE: [u8; 1] = [0];

    fn op_dup<'a>(stack: &mut Stack) -> StackResult<'a> {
        Ok(stack.last().unwrap().to_vec().into())
    }

    fn op_hash160<'a>(stack: &mut Stack) -> StackResult<'a> {
        let to_be_hashed = stack.pop();
        match to_be_hashed {
            Some(tbh) => {
                let hash = hash160::Hash::hash(&tbh);
                Ok(hash.to_vec().into())
            }
            None => {
                Err(VMError::EmptyStack)
            }
        }
    }

    fn op_equal<'a>(stack: &mut Stack) -> StackResult<'a> {
        let a = stack.pop();
        let b = stack.pop();

        if a.is_none() || b.is_none() {
            return Err(VMError::EmptyStack)
        }

        if a.iter().eq(b.iter()) {
            Ok((&RET_TRUE[..]).into())
        } else {
            Ok((&RET_FALSE[..]).into())
        }
    }

    fn op_verify<'a>(stack: &mut Stack) -> StackResult<'a> {
        let last = stack.pop();
        match last {
            Some(val) => {
                if val == &RET_TRUE[..] {
                    Ok((&RET_NONE[..]).into())
                } else {
                    Err(VMError::VerifyFailed)
                }
            }
            None => {
                Err(VMError::EmptyStack)
            }
        }
    }

    fn op_checksig<'a>(stack: &mut Stack) -> StackResult<'a> {
        // TODO: implement a ton of signature handling
        Ok((&RET_TRUE[..]).into())
    }

    #[test]
    fn verify_p2pkh_script() {

        let mut vm = ScriptVM{
            words: HashMap::new(),
            stack: Vec::new(),
        };
        vm.words.insert(all::OP_DUP.into_u8(), &[op_dup]);
        vm.words.insert(all::OP_HASH160.into_u8(), &[op_hash160]);
        // XXX superwords are awkward because the compiler can't tell that subsequent fn pointers should be the same type
        vm.words.insert(all::OP_EQUALVERIFY.into_u8(), &[op_equal, op_verify as OpHandler]);
        vm.words.insert(all::OP_CHECKSIG.into_u8(), &[op_checksig]);

        // These come from bitcoin's decodescript.py
        let signature = "304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e3bf630749894e342a022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee313d741ad0cfbc0c509001";
        let push_signature = ["48", signature].concat();
        let public_key = "03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2";
        let push_public_key = ["21", public_key].concat();
        let public_key_hash = "5dd1d3a048119c27b28293056724d9522f26d945";
        let push_public_key_hash = ["14", public_key_hash].concat();

        // PUSH <signature> PUSH <public_key>
        let script_sig = [push_signature, push_public_key].concat();

        // DUP HASH_160 PUSH <public_key_hash> EQUALVERIFY CHECKSIG
        let script_pub_key = ["76a9", &push_public_key_hash, "88ac"].concat();
            
        let raw = hex::decode([script_sig, script_pub_key].concat());
        let s = Script::from(raw.unwrap());

        for insn in s.iter(true) {
            match insn {
                Instruction::PushBytes(data) => {
                    println!("Pushing {:?}", data);
                    vm.stack.push(Cow::Borrowed(data));
                }
                Instruction::Op(op) => {
                    println!("Handling {:?}", op);
                    let handler = vm.words.get(&op.into_u8());
                    match handler {
                        Some(words) => {
                            for f in words.into_iter() {
                                match f(&mut vm.stack) {
                                    Ok(val) => {
                                        if val.len() > 0 {
                                            vm.stack.push(val);
                                        }
                                    }
                                    Err(_) => {
                                        // TODO: write a formatter for these errors
                                        panic!("Script failed.");
                                    }
                                }
                            }
                        }
                        None => {
                            panic!("Unsupported opcode: {:?}", op);
                        }
                    }
                }
                Instruction::Error(_) => {
                    println!("err");
                }
            }
        }
    }
}
