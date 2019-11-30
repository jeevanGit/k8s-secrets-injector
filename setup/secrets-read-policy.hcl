path "*" {
    capabilities = ["read", "list"]
}

path "secret/*" {
    capabilities = ["read", "list"]
}

path "secret/AC0001/*" {
    capabilities = ["read", "list"]
}
