//! Encoding spec markdown generator.
//!
//! When ran, this generator will:
//! - Get schema for all the types to be included in encoding docs
//! - Merge their definitions
//! - For each schema's declaration, look-up top-level definitions and format to
//!   md table
//! - For each non-top-level definition, format to md table
//!
//! Rebuild on changes with:
//! `cargo watch -x "run --bin anoma_encoding_spec" -i docs`

use std::collections::HashSet;
use std::io::Write;

use anoma::types::address::Address;
use anoma::types::transaction::pos;
use anoma::types::{token, transaction};
use borsh::{schema, BorshSchema};
use itertools::Itertools;
use lazy_static::lazy_static;
use madato::types::TableRow;

/// This generator will write output into this `docs` file.
const OUTPUT_PATH: &str = "docs/src/specs/encoding/generated-borsh-spec.md";

lazy_static! {
    /// Borsh types may be used by declarations. These are displayed differently in the [`md_fmt_type`].
    static ref BORSH_TYPES: HashSet<&'static str> =
        HashSet::from_iter([
            "string",
            "bool",
            "u8",
            "u16",
            "u32",
            "u64",
            "u128",
            "i8",
            "i16",
            "i32",
            "i64",
            "i128",
            "f32",
            "f64",
            // unit `()`
            "nil",
        ]);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = std::fs::File::create(OUTPUT_PATH).unwrap();

    write_generated_code_notice(&mut file)?;

    // Top-level definitions are displayed at the top
    let address_schema = Address::schema_container();
    let token_amount_schema = token::Amount::schema_container();
    let init_account_schema = transaction::InitAccount::schema_container();
    let init_validator_schema = transaction::InitValidator::schema_container();
    let token_transfer_schema = token::Transfer::schema_container();
    let update_vp_schema = transaction::UpdateVp::schema_container();
    let pos_bond_schema = pos::Bond::schema_container();
    let pos_withdraw_schema = pos::Withdraw::schema_container();
    let wrapper_tx_schema = transaction::WrapperTx::schema_container();
    let tx_type_schema = transaction::TxType::schema_container();

    // Merge type definitions
    let mut definitions = address_schema.definitions;
    // TODO check for conflicts (same name, different declaration)
    definitions.extend(token_amount_schema.definitions);
    definitions.extend(init_account_schema.definitions);
    definitions.extend(init_validator_schema.definitions);
    definitions.extend(token_transfer_schema.definitions);
    definitions.extend(update_vp_schema.definitions);
    definitions.extend(pos_bond_schema.definitions);
    definitions.extend(pos_withdraw_schema.definitions);
    definitions.extend(wrapper_tx_schema.definitions);
    definitions.extend(tx_type_schema.definitions);
    let mut tables: Vec<Table> = Vec::with_capacity(definitions.len());

    // Add the top-level definitions first
    let address_definition =
        definitions.remove(&address_schema.declaration).unwrap();
    let mut address_table =
        definition_to_table(address_schema.declaration, address_definition);
    address_table.add_rust_doc_link("https://docs.anoma.network/master/rustdoc/anoma/types/address/enum.Address.html");
    tables.push(address_table);

    let token_amount_definition = definitions
        .remove(&token_amount_schema.declaration)
        .unwrap();
    let mut token_amount_table = definition_to_table(
        token_amount_schema.declaration,
        token_amount_definition,
    );
    token_amount_table.add_rust_doc_link("https://docs.anoma.network/master/rustdoc/anoma/types/token/struct.Amount.html");
    tables.push(token_amount_table);

    let init_account_definition = definitions
        .remove(&init_account_schema.declaration)
        .unwrap();
    let mut init_account_table = definition_to_table(
        init_account_schema.declaration,
        init_account_definition,
    );
    init_account_table.add_rust_doc_link("https://docs.anoma.network/master/rustdoc/anoma/types/transaction/struct.InitAccount.html");
    tables.push(init_account_table);

    let init_validator_definition = definitions
        .remove(&init_validator_schema.declaration)
        .unwrap();
    let mut init_validator_table = definition_to_table(
        init_validator_schema.declaration,
        init_validator_definition,
    );
    init_validator_table.add_rust_doc_link("https://docs.anoma.network/master/rustdoc/anoma/types/transaction/struct.InitValidator.html");
    tables.push(init_validator_table);

    let token_transfer_definition = definitions
        .remove(&token_transfer_schema.declaration)
        .unwrap();
    let mut token_transfer_table = definition_to_table(
        token_transfer_schema.declaration,
        token_transfer_definition,
    );
    token_transfer_table.add_rust_doc_link("https://docs.anoma.network/master/rustdoc/anoma/types/token/struct.Transfer.html");
    tables.push(token_transfer_table);

    let update_vp_definition =
        definitions.remove(&update_vp_schema.declaration).unwrap();
    let mut update_vp_table =
        definition_to_table(update_vp_schema.declaration, update_vp_definition);
    update_vp_table.add_rust_doc_link("https://docs.anoma.network/master/rustdoc/anoma/types/transaction/struct.UpdateVp.html");
    tables.push(update_vp_table);

    let pos_bond_definition =
        definitions.remove(&pos_bond_schema.declaration).unwrap();
    let mut pos_bond_table =
        definition_to_table(pos_bond_schema.declaration, pos_bond_definition);
    pos_bond_table.add_rust_doc_link("https://docs.anoma.network/master/rustdoc/anoma/types/transaction/pos/struct.Bond.html");
    tables.push(pos_bond_table);

    let pos_withdraw_definition = definitions
        .remove(&pos_withdraw_schema.declaration)
        .unwrap();
    let mut pos_withdraw_table = definition_to_table(
        pos_withdraw_schema.declaration,
        pos_withdraw_definition,
    );
    pos_withdraw_table.add_rust_doc_link("https://docs.anoma.network/master/rustdoc/anoma/types/transaction/pos/struct.Withdraw.html");
    tables.push(pos_withdraw_table);

    let wrapper_tx_definition =
        definitions.remove(&wrapper_tx_schema.declaration).unwrap();
    let mut wrapper_tx_table = definition_to_table(
        wrapper_tx_schema.declaration,
        wrapper_tx_definition,
    );
    wrapper_tx_table.add_rust_doc_link("https://docs.anoma.network/master/rustdoc/anoma/types/transaction/wrapper/wrapper_tx/struct.WrapperTx.html");
    tables.push(wrapper_tx_table);

    let tx_type_definition =
        definitions.remove(&tx_type_schema.declaration).unwrap();
    let mut tx_type_table =
        definition_to_table(tx_type_schema.declaration, tx_type_definition);
    tx_type_table.add_rust_doc_link("https://docs.anoma.network/master/rustdoc/anoma/types/transaction/tx_types/enum.TxType.html");
    tables.push(tx_type_table);

    // Then add the rest of definitions sorted by their names
    for (declaration, defition) in definitions
        .into_iter()
        .sorted_by_key(|(key, _val)| key.clone())
    {
        tables.push(definition_to_table(declaration, defition))
    }

    // Print the tables to markdown
    for table in tables {
        writeln!(file, "#### {}", escape_html(table.name))?;
        writeln!(file)?;
        writeln!(file, "{}", table.desc)?;
        writeln!(file)?;
        if let Some(rows) = table.rows {
            let md_table = madato::mk_table(&rows[..], &None);
            writeln!(file, "{}", md_table)?;
            writeln!(file)?;
        }
    }

    writeln!(file)?;
    write_generated_code_notice(&mut file)?;

    Ok(())
}

struct Table {
    name: String,
    desc: String,
    rows: Option<madato::types::Table<String, String>>,
}

fn definition_to_table(name: String, def: schema::Definition) -> Table {
    let (desc, rows) = match def {
        schema::Definition::Array { length, elements } => {
            let rows = None;
            let desc = format!(
                "Fixed-size array with {} elements of {}",
                length,
                md_fmt_type(elements)
            );
            (desc, rows)
        }
        schema::Definition::Sequence { elements } => {
            let rows = None;
            let desc =
                format!("Dynamic-size array of {}", md_fmt_type(elements));
            (desc, rows)
        }
        schema::Definition::Tuple { elements } => {
            let rows = None;
            let desc = format!(
                "Tuple of ({})",
                elements.into_iter().fold(String::new(), |acc, element| {
                    if acc.is_empty() {
                        md_fmt_type(element)
                    } else {
                        format!("{}, {}", acc, md_fmt_type(element))
                    }
                })
            );
            (desc, rows)
        }
        schema::Definition::Enum { variants } => {
            let mut rows = madato::types::Table::default();
            // build rows for: Variant, Name, Type
            for (variant, (name, type_name)) in variants.iter().enumerate() {
                rows.push(TableRow::from_iter([
                    ("Prefix byte".into(), variant.to_string()),
                    ("Name".into(), name.clone()),
                    ("Type".into(), md_fmt_type(type_name)),
                ]));
            }
            ("Enum".into(), Some(rows))
        }
        schema::Definition::Struct { fields } => {
            match fields {
                schema::Fields::NamedFields(fields) => {
                    let mut rows = madato::types::Table::default();
                    // build rows for: Position, Name, Type
                    for (variant, (name, type_name)) in
                        fields.iter().enumerate()
                    {
                        rows.push(TableRow::from_iter([
                            ("Position".into(), variant.to_string()),
                            ("Name".into(), name.clone()),
                            ("Type".into(), md_fmt_type(type_name)),
                        ]));
                    }
                    ("Struct with named fields".into(), Some(rows))
                }
                schema::Fields::UnnamedFields(fields) => {
                    let mut rows = madato::types::Table::default();
                    // build rows for: Field, Type
                    for (variant, type_name) in fields.iter().enumerate() {
                        rows.push(TableRow::from_iter([
                            ("Position".into(), variant.to_string()),
                            ("Type".into(), md_fmt_type(type_name)),
                        ]));
                    }
                    ("Struct with unnamed fields".into(), Some(rows))
                }
                schema::Fields::Empty => ("Empty struct (unit)".into(), None),
            }
        }
    };
    Table { name, desc, rows }
}

/// Format a type to markdown. For internal types, adds anchors.
fn md_fmt_type(type_name: impl AsRef<str>) -> String {
    if BORSH_TYPES.contains(type_name.as_ref()) {
        let type_name = escape_html(type_name);
        format!("{} (native type)", type_name)
    } else {
        let type_link = escape_fragment_anchor(&type_name);
        let type_name = escape_html(type_name);
        format!("[{}](#{})", type_name, type_link)
    }
}

fn write_generated_code_notice(
    file: &mut std::fs::File,
) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(
        file,
        "<!--- THIS PAGE IS GENERATED FROM CODE: {}. Do not edit manually! -->",
        std::file!()
    )?;
    Ok(())
}

/// Escape a type for markdown (rendered as HTML)
fn escape_html(string: impl AsRef<str>) -> String {
    string.as_ref().replace('>', "&gt;").replace('<', "&lt;")
}

/// Escape a link to another type on the page
fn escape_fragment_anchor(string: impl AsRef<str>) -> String {
    // mdBook turns headings fragment links to lowercase
    string
        .as_ref()
        .replace('>', "")
        .replace('<', "")
        .replace(',', "")
        .replace(' ', "-")
        .to_ascii_lowercase()
}

impl Table {
    /// Add a link to rust-docs
    fn add_rust_doc_link(&mut self, link: impl AsRef<str>) {
        self.desc = format!("{} ([rust-doc]({}))", self.desc, link.as_ref());
    }
}
