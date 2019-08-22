use crate::build;

use failure::Error;

fn check_optimize_contract(origin: &str, expected: &str) -> Result<(), Error> {
    let origin = wabt::wat2wasm(origin).expect("origin wast must be valid");
    let expected = wabt::wat2wasm(expected).expect("origin wast must be valid");
    let origin = parity_wasm::deserialize_buffer(&origin).expect("origin wast must be valid");
    let module = build::build(origin, true)?;

    let buf = parity_wasm::serialize(module)?;
    assert_eq!(buf, expected);

    Ok(())
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
