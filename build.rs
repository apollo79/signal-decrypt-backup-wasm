fn main() {
    let mut config = prost_build::Config::new();
    config.bytes(&["."]);
    config.type_attribute(".", "#[derive(::serde::Serialize, ::serde::Deserialize)]");

    // For bytes fields, use with = "crate::bytes_serde"
    config.field_attribute(
        ".signal.SqlStatement.SqlParameter.blobParameter",
        "#[serde(with = \"crate::bytes_serde\")]",
    );
    config.field_attribute(
        ".signal.Header.iv",
        "#[serde(with = \"crate::bytes_serde\")]",
    );
    config.field_attribute(
        ".signal.Header.salt",
        "#[serde(with = \"crate::bytes_serde\")]",
    );
    config.field_attribute(
        ".signal.KeyValue.blobValue",
        "#[serde(with = \"crate::bytes_serde\")]",
    );

    config
        .compile_protos(&["src/signal.proto"], &["src/"])
        .unwrap();
}
