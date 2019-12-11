function Encrypt{param($data, $password, $keySize = 256)
    $aesProvider = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aesProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesProvider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesProvider.KeySize = $keySize
    $aesProvider.GenerateIV()

    #We are not saving this hash, we do not need to salt it
    $aesProvider.Key = (New-Object System.Security.Cryptography.PasswordDeriveBytes($password, (New-Object byte[] 0))).GetBytes($aesProvider.BlockSize / 8)

    $memStream = New-Object System.IO.MemoryStream
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memStream, $aesProvider.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)
    $cryptoStream.Write($data, 0, $data.Length)
    $cryptoStream.FlushFinalBlock()

    $encrypted = New-Object byte[]($memStream.Length + $aesProvider.IV.Length)
    [array]::Copy($aesProvider.IV, 0, $encrypted, 0, $aesProvider.IV.Length)
    [array]::Copy($memStream.ToArray(), 0, $encrypted, $aesProvider.IV.Length, $memStream.ToArray().Length)
    return $encrypted
}

function Decrypt{param([byte[]]$data, $password, $keySize = 256)
    $aesProvider = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aesProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesProvider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesProvider.KeySize = $keySize
    $aesProvider.IV = [System.Linq.Enumerable]::Take($data, $aesProvider.BlockSize / 8)

    #We are not saving this hash, we do not need to salt it
    $aesProvider.Key = (New-Object System.Security.Cryptography.PasswordDeriveBytes($password, (New-Object byte[] 0))).GetBytes($aesProvider.BlockSize / 8)

    $decrypted = New-Object byte[]($data.Length - $aesProvider.IV.Length)
    $memStream = New-Object System.IO.MemoryStream(,[System.Linq.Enumerable]::Skip($data, $aesProvider.IV.Length))
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memStream, $aesProvider.CreateDecryptor(), [System.Security.Cryptography.CryptoStreamMode]::Read)
    $bytesRead = $cryptoStream.Read($decrypted, 0, $decrypted.Length)
    return [System.Linq.Enumerable]::Take($decrypted, $bytesRead)
}

function DecryptString {param ($textData, $password, $keySize = 256)
    $encryptedBytes = [System.Convert]::FromBase64String($textData)
    return Decrypt $encryptedBytes $password $keySize
}

function DecryptToString {param ($textData, $password, $keySize = 256)
    $encryptedBytes = [System.Convert]::FromBase64String($textData)
    return [System.Text.Encoding]::UTF8.GetString((Decrypt $encryptedBytes $password $keySize))
}

function EncryptString {param ($textData, $password, $keySize = 256)
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($textData)
    return Encrypt $plainBytes $password $keySize
}

function EncryptToString {param ($textData, $password, $keySize = 256)
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($textData)
    return [Convert]::ToBase64String((Encrypt $plainBytes $password $keySize))
}
