## ontio-wasm-build

[![Build Status](https://travis-ci.com/ontio/ontio-wasm-build.svg?branch=master)](https://travis-ci.com/ontio/ontio-wasm-build)

[English](README.md) | 中文

`ontio-wasm-build`是Ontology wasm合约的校验和优化工具，在部署合约到链上前，使用该工具能够对wasm合约的二进制码进行解析校验，同时对合约中无效的信息进行清理删除，缩减合约的大小，减少部署费用。

主要的检查优化项：
* 合约存在入口函数`invoke`,参数和返回值均为空;
* 清理合约中没有使用的函数，导入导出项;
* 检查合约中的浮点数指令;
* 检查所有导入项为Ontology runtime api，且输入输出参数完全匹配;
* 检查合约的内存和Table使用上限是否超过规定的值，防止恶意的合约攻击
* 清理data section中的零值
* 清理custom section
* 检查优化后的合约大小不超过规定值

## 安装方式
可以使用以下任一种方式进行安装：
1. 从[releases](https://github.com/ontio/ontio-wasm-build/releases)中直接下载二进制
2. cargo install安装
```bash
cargo install --git=https://github.com/ontio/ontio-wasm-build
```
3. 源码安装
```bash
git clone https://github.com/ontio/ontio-wasm-build
cd ontio-wasm-build
cargo build --release
```

## 使用方式
```
$ ontio-wasm-build --help
ontio-wasm-build 0.1.0

USAGE:
    ontio-wasm-build [FLAGS] <input> <output>

FLAGS:
    -h, --help           Prints help information
        --keep-custom    Keep custom section in output wasm file
    -V, --version        Prints version information

ARGS:
    <input>     Wasm file generated by rustc compiler
    <output>    Output wasm file name
```

`input`参数用来指定要优化的wasm合约文件，可使用[ontology-wasm-cdt-cpp](https://github.com/ontio/ontology-wasm-cdt-cpp)或者[ontology-wasm-cdt-rust](https://github.com/ontio/ontology-wasm-cdt-rust)开发生成。

`output`参数用来指定优化后的wasm合约文件名

`keep-custom`用来设置输出的wasm文件是否保留`custom_section`,只用于调试用

## License

This project is licensed under the [MIT license](LICENSE).
