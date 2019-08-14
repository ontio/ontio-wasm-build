use parity_wasm::elements::{
    External, FuncBody, FunctionType, InitExpr, Instruction, Internal, Module, Type, ValueType,
};

use failure::{err_msg, Error};
use pwasm_utils::optimize;

pub fn build(mut module: Module, nocustom: bool) -> Result<Module, Error> {
    if module.start_section().is_some() {
        return Err(err_msg("start section is not allowed"));
    }

    optimize(&mut module, vec!["invoke"])
        .map_err(|e| err_msg(format!("failed to optimize: {:?}", e)))?;

    // check invoke signature
    match module.export_section() {
        None => return Err(err_msg("invoke function is not exposrted")),
        Some(export) => {
            assert_eq!(
                export.entries().len(),
                1,
                "number of export extries must be 1 after optimization"
            );
            let invoke = &export.entries()[0];
            assert_eq!(invoke.field(), "invoke");
            match invoke.internal() {
                Internal::Function(index) => {
                    let sec_index = *index as usize - import_function_count(&module);
                    let sig_index =
                        module.function_section().unwrap().entries()[sec_index].type_ref();
                    let func_type = &module.type_section().unwrap().types()[sig_index as usize];
                    match func_type {
                        Type::Function(func_type) => {
                            if func_type.params().len() != 0 || func_type.return_type() != None {
                                return Err(err_msg("signature mismatch for func: invoke"));
                            }
                        }
                    }
                }
                _ => return Err(err_msg("invoke is not a export function")),
            }
        }
    }

    deny_floating_point(&module)?;

    check_import_section(&module)?;

    clean_zeros_in_data_section(&mut module);

    if nocustom {
        let names: Vec<String> =
            module.custom_sections().map(|elem| elem.name().to_string()).collect();
        for name in &names {
            module.clear_custom_section(name);
        }

        assert_eq!(module.custom_sections().count(), 0);
    }

    Ok(module)
}

const SIGNATURES: [(&str, &[ValueType], Option<ValueType>); 19] = [
    ("timestamp", &[], Some(ValueType::I64)),
    ("block_height", &[], Some(ValueType::I32)),
    ("input_length", &[], Some(ValueType::I32)),
    ("call_output_length", &[], Some(ValueType::I32)),
    ("get_input", &[ValueType::I32], None),
    ("get_output", &[ValueType::I32], None),
    ("self_address", &[ValueType::I32], None),
    ("caller_address", &[ValueType::I32], None),
    ("entry_address", &[ValueType::I32], None),
    ("check_witness", &[ValueType::I32], Some(ValueType::I32)),
    ("check_witness", &[ValueType::I32], Some(ValueType::I32)),
    ("current_blockhash", &[ValueType::I32], Some(ValueType::I32)),
    ("current_txhash", &[ValueType::I32], Some(ValueType::I32)),
    ("ret", &[ValueType::I32; 2], None),
    ("call_contract", &[ValueType::I32; 3], Some(ValueType::I32)),
    ("contract_migrate", &[ValueType::I32; 14], Some(ValueType::I32)),
    ("storage_read", &[ValueType::I32; 5], Some(ValueType::I32)),
    ("storage_write", &[ValueType::I32; 4], None),
    ("storage_delete", &[ValueType::I32; 2], None),
];

fn check_import_section(module: &Module) -> Result<(), Error> {
    if let Some(import_section) = module.import_section() {
        for import_entry in import_section.entries() {
            if import_entry.module() != "env" {
                return Err(err_msg(format!(
                    "import module should be env, got: {}",
                    import_entry.module()
                )));
            }

            match import_entry.external() {
                External::Function(index) => {
                    let func_type = &module.type_section().unwrap().types()[*index as usize];
                    match func_type {
                        Type::Function(func_type) => {
                            check_signature(import_entry.field(), func_type)?;
                        }
                    }
                }
                _ => return Err(err_msg("only function can be imported from ontology runtime")),
            };
        }
    }
    return Ok(());
}

fn check_signature(func: &str, func_type: &FunctionType) -> Result<(), Error> {
    match SIGNATURES.iter().find(|e| e.0 == func) {
        None => return Err(err_msg(format!("can not find signature for func: {}", func))),
        Some(sig) => {
            if sig.2 != func_type.return_type()
                || sig.1.len() != func_type.params().len()
                || sig.1.iter().zip(func_type.params()).any(|(a, b)| a != b)
            {
                return Err(err_msg(format!(
                    "signature mismatch for func: {}, expect:{:?}, got: {:?}",
                    func,
                    sig.1,
                    func_type.params()
                )));
            }
        }
    }

    Ok(())
}

fn is_float_inst(inst: &Instruction) -> bool {
    let inst = format!("{}", inst);
    return inst.contains("f32") || inst.contains("f64");
}

fn is_float_type(value_type: &ValueType) -> bool {
    match value_type {
        ValueType::I32 | ValueType::I64 => return false,
        _ => return false,
    }
}

fn is_float_init_expr(init_expr: &InitExpr) -> bool {
    for expr in init_expr.code() {
        if is_float_inst(&expr) {
            return true;
        }
    }

    false
}

fn deny_floating_point(module: &Module) -> Result<(), Error> {
    if let Some(code) = module.code_section() {
        let bodies: &[FuncBody] = code.bodies();
        for body in bodies {
            let locals = body.locals();
            for local in locals {
                if is_float_type(&local.value_type()) {
                    return Err(err_msg("function local variable contains floating type"));
                }
            }
        }
    }

    if let Some(global_section) = module.global_section() {
        let entries = global_section.entries();
        for entry in entries {
            if is_float_type(&entry.global_type().content_type()) {
                return Err(err_msg(format!(
                    "global type content type is invalid: {}",
                    &entry.global_type().content_type()
                )));
            }
            if is_float_init_expr(entry.init_expr()) {
                return Err(err_msg("global init expr contains floating type"));
            }
        }
    }

    if let Some(data_section) = module.data_section() {
        for data_segment in data_section.entries() {
            if let Some(init_expr) = data_segment.offset() {
                if is_float_init_expr(init_expr) {
                    return Err(err_msg("init expr in data section contains floating type"));
                }
            }
        }
    }
    if let Some(elements_section) = module.elements_section() {
        for entry in elements_section.entries() {
            if let Some(init_expr) = entry.offset() {
                if is_float_init_expr(init_expr) {
                    return Err(err_msg("init expr in element section contains floating type"));
                }
            }
        }
    }

    // type section and function code is checked in wasmi
    let wasmi_module = wasmi::Module::from_parity_wasm_module(module.clone())?;
    wasmi_module.deny_floating_point()?;

    Ok(())
}

fn clean_zeros_in_data_section(module: &mut Module) {
    match module.data_section_mut() {
        None => return,
        Some(data) => {
            let zero_index = data
                .entries()
                .iter()
                .enumerate()
                .filter(|elem| elem.1.value().iter().all(|e| *e == 0))
                .map(|(index, _)| index)
                .collect::<Vec<_>>();

            for ind in zero_index.into_iter().rev() {
                data.entries_mut().remove(ind);
            }
        }
    }
}

fn import_function_count(module: &Module) -> usize {
    module.import_section().map(|import| import.functions()).unwrap_or(0)
}

#[allow(dead_code)]
fn dump_module(module: &Module) {
    let buf = parity_wasm::serialize(module.clone()).unwrap();
    let wat = wabt::wasm2wat(buf).unwrap();

    println!("{}", wat);
}
