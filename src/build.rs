use parity_wasm::elements::{
    External, FuncBody, FunctionType, InitExpr, Instruction, Internal, MemoryType, Module,
    TableType, Type, ValueType,
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
        None => return Err(err_msg("invoke function is not exported")),
        Some(export) => {
            if export.entries().len() != 1 {
                return Err(err_msg("invoke function is not exported"));
            }
            let invoke = &export.entries()[0];
            assert_eq!(invoke.field(), "invoke");
            match invoke.internal() {
                Internal::Function(index) => {
                    let imp_func_count = import_function_count(&module);
                    let sig_index = if (*index as usize) < imp_func_count {
                        import_funcion_indexes(&module)[*index as usize]
                    } else {
                        let sec_index = *index as usize - import_function_count(&module);
                        module.function_section().unwrap().entries()[sec_index].type_ref()
                    };
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

    check_limits(&mut module)?;

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

const SIGNATURES: [(&str, &[ValueType], Option<ValueType>); 21] = [
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
    ("current_blockhash", &[ValueType::I32], Some(ValueType::I32)),
    ("current_txhash", &[ValueType::I32], Some(ValueType::I32)),
    ("ret", &[ValueType::I32; 2], None),
    ("notify", &[ValueType::I32; 2], None),
    ("call_contract", &[ValueType::I32; 3], Some(ValueType::I32)),
    ("contract_migrate", &[ValueType::I32; 14], Some(ValueType::I32)),
    ("contract_destroy", &[], None),
    ("storage_read", &[ValueType::I32; 5], Some(ValueType::I32)),
    ("storage_write", &[ValueType::I32; 4], None),
    ("storage_delete", &[ValueType::I32; 2], None),
    ("debug", &[ValueType::I32; 2], None),
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

fn import_funcion_indexes(module: &Module) -> Vec<u32> {
    module
        .import_section()
        .map(|import| {
            import
                .entries()
                .iter()
                .filter_map(|entry| match entry.external() {
                    External::Function(ind) => Some(*ind),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

const PAGE_SIZE: u32 = 64 * 1024;
const MAX_MEM_PAGE: u32 = 80;
const MAX_TABLE_SIZE: u32 = 1024;

// check memory and table limits, if upper bound is not specified, it will be replaced with the default
// max value, so the arg is a mutable ref.
fn check_limits(module: &mut Module) -> Result<(), Error> {
    let init_mem = initial_memory_size_in_data_section(module) as u32;
    if let Some(mem) = module.memory_section_mut() {
        let entries = mem.entries_mut();
        if entries.len() > 1 {
            return Err(err_msg("no more than one memory definition"));
        }
        let limit = entries[0].limits();
        let (initial, maximum) = (limit.initial(), limit.maximum());
        let stack_size = initial * PAGE_SIZE - init_mem;
        if stack_size > 1 * PAGE_SIZE || initial > MAX_MEM_PAGE {
            return Err(err_msg("initial memory size too large, plase use `RUSTFLAGS=\"-C link-arg=-zstack-size=32768\" cargo build`"));
        }
        if maximum.unwrap_or(MAX_MEM_PAGE) >= MAX_MEM_PAGE {
            entries[0] = MemoryType::new(initial, Some(MAX_MEM_PAGE));
        }
    }

    if let Some(table) = module.table_section_mut() {
        let entries = table.entries_mut();
        if entries.len() > 1 {
            return Err(err_msg("no more than one table definition"));
        }
        let limit = entries[0].limits();
        let (initial, maximum) = (limit.initial(), limit.maximum());
        if initial > MAX_TABLE_SIZE {
            return Err(err_msg("initial table size too large"));
        }
        if maximum.unwrap_or(MAX_TABLE_SIZE) >= MAX_TABLE_SIZE {
            entries[0] = TableType::new(initial, Some(MAX_TABLE_SIZE));
        }
    }

    Ok(())
}

fn initial_memory_size_in_data_section(module: &Module) -> usize {
    module
        .data_section()
        .map(|data| data.entries().iter().map(|entry| entry.value().len()).sum())
        .unwrap_or_default()
}

#[allow(dead_code)]
fn dump_module(title: &str, module: &Module) {
    println!("{}", title);
    let buf = parity_wasm::serialize(module.clone()).unwrap();
    let wat = wabt::wasm2wat(buf).unwrap();

    println!("{}", wat);
}
