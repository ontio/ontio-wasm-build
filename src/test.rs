use crate::build;

use anyhow::Error;

fn check_optimize_contract(origin: &str, expected: &str) {
    let origin = wabt::wat2wasm(origin).expect("origin wast must be valid");
    let expected = wabt::wat2wasm(expected).expect("origin wast must be valid");
    let origin = parity_wasm::deserialize_buffer(&origin).expect("origin wast must be valid");
    let module = build::build(origin, true).expect("build should not fail");

    let buf = parity_wasm::serialize(module).expect("serialize should not fail");
    assert_eq!(buf, expected);
}

// invalid contract
fn check_invalid_contract(origin: &str) -> Error {
    let origin = wabt::wat2wasm(origin).expect("origin wast must be valid");
    let origin = parity_wasm::deserialize_buffer(&origin).expect("origin wast must be valid");
    match build::build(origin, true) {
        Ok(_) => panic!("invalid contract should fail"),
        Err(e) => return e,
    }
}

fn check_valid_contract(origin: &str) {
    let origin = wabt::wat2wasm(origin).expect("origin wast must be valid");
    let origin = parity_wasm::deserialize_buffer(&origin).expect("origin wast must be valid");
    match build::build(origin, true) {
        Err(e) => panic!(e),
        Ok(_) => return,
    }
}

#[test]
fn test_table_limit() {
    check_valid_contract(
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (table (;0;) 1 10 funcref)
    (export "invoke" (func 0))
    )
    "#,
    );

    // exceed initial size
    dbg!(check_invalid_contract(
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (table (;0;) 1025 1025 funcref)
    (export "invoke" (func 0))
    )
    "#,
    ));

    // exceed max size
    check_optimize_contract(
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (table (;0;) 1 1025 funcref)
    (export "invoke" (func 0))
    )
    "#,
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (table (;0;) 1 1024 funcref)
    (export "invoke" (func 0))
    )
    "#,
    );

    // no max size
    check_optimize_contract(
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (table (;0;) 1  funcref)
    (export "invoke" (func 0))
    )
    "#,
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (table (;0;) 1 1024 funcref)
    (export "invoke" (func 0))
    )
    "#,
    );
}

#[test]
fn test_mem_limit() {
    check_valid_contract(
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (memory (;0;) 1 10)
    (export "invoke" (func 0))
    )
    "#,
    );

    // exceed initial size
    dbg!(check_invalid_contract(
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (memory (;0;) 10 10)
    (export "invoke" (func 0))
    )
    "#,
    ));

    // exceed max size
    check_optimize_contract(
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (memory (;0;) 1 81)
    (export "invoke" (func 0))
    )
    "#,
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (memory (;0;) 1 80)
    (export "invoke" (func 0))
    )
    "#,
    );

    // no max size
    check_optimize_contract(
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (memory (;0;) 1 )
    (export "invoke" (func 0))
    )
    "#,
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (memory (;0;) 1 80)
    (export "invoke" (func 0))
    )
    "#,
    );
}

#[test]
fn test_import() {
    check_valid_contract(
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (export "invoke" (func 0))
    )
    "#,
    );

    // only import runtime function is valid
    check_invalid_contract(
        r#"
    (module
    (type (;0;) (func))
    (import "env" "add" (func (type 0)))
    (func (;1;))
    (export "invoke" (func 0))
    )
    "#,
    );

    // only import from `env` is valid
    check_invalid_contract(
        r#"
    (module
    (type (;0;) (func))
    (import "othermodule" "add" (func (type 0)))
    (func (;1;))
    (export "invoke" (func 0))
    )
    "#,
    );
}

#[test]
fn test_empty() {
    check_invalid_contract(r#" (module ) "#);
    check_invalid_contract(
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (export "invok" (func 0))
    )
    "#,
    );

    check_valid_contract(
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (export "invoke" (func 0))
    )
    "#,
    );

    check_valid_contract(
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (export "invoke" (func 0))
    (export "invoke2" (func 0))
    )
    "#,
    );

    check_optimize_contract(
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (export "invoke" (func 0))
    (export "invoke2" (func 0))
    )
    "#,
        r#"
    (module
    (type (;0;) (func))
    (func (;0;))
    (export "invoke" (func 0))
    )
    "#,
    );
}
